// Copyright 2019 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#include "tink/subtle/decrypting_random_access_stream.h"

#include <algorithm>
#include <cstring>
#include <vector>

#include "absl/base/thread_annotations.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/synchronization/mutex.h"
#include "tink/random_access_stream.h"
#include "tink/subtle/stream_segment_decrypter.h"
#include "tink/util/buffer.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

using crypto::tink::RandomAccessStream;
using crypto::tink::ToStatusF;
using crypto::tink::util::Buffer;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;

// static
StatusOr<std::unique_ptr<RandomAccessStream>> DecryptingRandomAccessStream::New(
    std::unique_ptr<StreamSegmentDecrypter> segment_decrypter,
    std::unique_ptr<RandomAccessStream> ciphertext_source) {
  if (segment_decrypter == nullptr) {
    return Status(util::error::INVALID_ARGUMENT,
                  "segment_decrypter must be non-null");
  }
  if (ciphertext_source == nullptr) {
    return Status(util::error::INVALID_ARGUMENT,
                  "cipertext_source must be non-null");
  }
  std::unique_ptr<DecryptingRandomAccessStream> dec_stream(
      new DecryptingRandomAccessStream());
  absl::MutexLock lock(&(dec_stream->status_mutex_));
  dec_stream->segment_decrypter_ = std::move(segment_decrypter);
  dec_stream->ct_source_ = std::move(ciphertext_source);

  if (dec_stream->segment_decrypter_->get_ciphertext_offset() < 0) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "The ciphertext offset must be non-negative");
  }
  int first_segment_size =
      dec_stream->segment_decrypter_->get_plaintext_segment_size() -
      dec_stream->segment_decrypter_->get_ciphertext_offset() -
      dec_stream->segment_decrypter_->get_header_size();
  if (first_segment_size <= 0) {
    return Status(util::error::INVALID_ARGUMENT,
                  "Size of the first segment must be greater than 0.");
  }
  dec_stream->status_ =
      Status(util::error::UNAVAILABLE, "The header hasn't been read yet.");
  return {std::move(dec_stream)};
}

util::Status DecryptingRandomAccessStream::PRead(int64_t position, int count,
                                                 Buffer* dest_buffer) {
  if (dest_buffer == nullptr) {
    return Status(util::error::INVALID_ARGUMENT,
                  "dest_buffer must be non-null");
  }
  auto status = dest_buffer->set_size(0);
  if (!status.ok()) return status;
  if (count < 0) {
    return Status(util::error::INVALID_ARGUMENT, "count cannot be negative");
  }
  if (count > dest_buffer->allocated_size()) {
    return Status(util::error::INVALID_ARGUMENT, "buffer too small");
  }
  if (position < 0) {
    return Status(util::error::INVALID_ARGUMENT, "position cannot be negative");
  }

  {  // Initialize, if not initialized yet.
    absl::MutexLock lock(&status_mutex_);
    InitializeIfNeeded();
    if (!status_.ok()) return status_;
  }

  if (position > pt_size_) {
    return Status(util::error::INVALID_ARGUMENT, "position too large");
  }
  return PReadAndDecrypt(position, count, dest_buffer);
}

// NOTE: As the initialization below requires availability of size() of the
// underlying ciphertext stream, the current implementation does not support
// dynamic encrypted streams, whose size is not known or can change over time
// (e.g. when one process produces an encrypted file/stream, while concurrently
// another process consumes the resulting encrypted stream).
//
// This is consistent with Java implementation of SeekableDecryptingChannel,
// and detects ciphertext truncation attacks.  However, a support for dynamic
// streams can be added in the future if needed.
void DecryptingRandomAccessStream::InitializeIfNeeded()
    ABSL_EXCLUSIVE_LOCKS_REQUIRED(status_mutex_) {
  if (status_.code() != absl::StatusCode::kUnavailable) {
    // Already initialized or stream failed permanently.
    return;
  }

  // Initialize segment decrypter from data in the stream header.
  header_size_ = segment_decrypter_->get_header_size();
  ct_offset_ = segment_decrypter_->get_ciphertext_offset();
  auto buf_result = Buffer::New(header_size_);
  if (!buf_result.ok()) {
    status_ = buf_result.status();
    return;
  }
  auto buf = std::move(buf_result.ValueOrDie());
  status_ = ct_source_->PRead(ct_offset_, header_size_, buf.get());
  if (!status_.ok()) {
    if (status_.code() == absl::StatusCode::kOutOfRange) {
      status_ = Status(util::error::INVALID_ARGUMENT, "could not read header");
    }
    return;
  }
  status_ = segment_decrypter_->Init(std::vector<uint8_t>(
      buf->get_mem_block(), buf->get_mem_block() + header_size_));
  if (!status_.ok()) return;
  ct_segment_size_ = segment_decrypter_->get_ciphertext_segment_size();
  pt_segment_size_ = segment_decrypter_->get_plaintext_segment_size();
  ct_segment_overhead_ = ct_segment_size_ - pt_segment_size_;

  // Calculate the number of segments and the plaintext size.
  StatusOr<int64_t> ct_size_result = ct_source_->size();
  if (!ct_size_result.ok()) {
    status_ = ct_size_result.status();
    return;
  }
  int64_t ct_size = ct_size_result.ValueOrDie();
  // ct_segment_size_ is always larger than 1, thus full_segment_count is always
  // smaller than std::numeric_limits<int64_t>::max().
  int64_t full_segment_count = ct_size / ct_segment_size_;
  int64_t remainder_size = ct_size % ct_segment_size_;
  if (remainder_size > 0) {
    // This does not overflow because full_segment_count <
    // std::numeric_limits<int64_t>::max().
    segment_count_ = full_segment_count + 1;
  } else {
    segment_count_ = full_segment_count;
  }
  // Tink supports up to 2^32 segments.
  if (segment_count_ - 1 > std::numeric_limits<uint32_t>::max()) {
    status_ = Status(util::error::INVALID_ARGUMENT,
                     absl::StrCat("too many segments: ", segment_count_));
    return;
  }

  // This should not overflow because:
  // * segment_count is int64 and smaller than 2^32, and
  // * ct_segment_overhead_, ct_offset_ and header_size_ are small int numbers.
  auto overhead =
      ct_segment_overhead_ * segment_count_ + ct_offset_ + header_size_;
  if (overhead > ct_size) {
    status_ = Status(util::error::INVALID_ARGUMENT,
                     "ciphertext stream is too short");
    return;
  }
  pt_size_ = ct_size - overhead;
}

int DecryptingRandomAccessStream::GetPlaintextOffset(int64_t pt_position) {
  if (GetSegmentNr(pt_position) == 0) return pt_position;
  // Computed according to the formula:
  // (pt_position - (pt_segment_size_ - ct_offset_ - header_size_))
  //     % pt_segment_size_;
  // pt_position + ct_offset_ + header_size_ is always smaller than size of
  // the ciphertext, thus it should never overflow.
  return (pt_position + ct_offset_ + header_size_) % pt_segment_size_;
}

int64_t DecryptingRandomAccessStream::GetSegmentNr(int64_t pt_position) {
  return (pt_position + ct_offset_ + header_size_) / pt_segment_size_;
}

util::Status DecryptingRandomAccessStream::ReadAndDecryptSegment(
    int64_t segment_nr, Buffer* ct_buffer, std::vector<uint8_t>* pt_segment) {
  int64_t ct_position = segment_nr * ct_segment_size_;
  if (ct_position / ct_segment_size_ != segment_nr /* overflow occured! */) {
    return Status(util::error::OUT_OF_RANGE,
                  absl::StrCat("segment_nr * ct_segment_size too large: ",
                               segment_nr, ct_segment_size_));
  }
  int segment_size = ct_segment_size_;
  if (segment_nr == 0) {
    // The sum of ct_offset_ and header_size is always smaller than
    // ct_segment_size_, which is an int, therefore the next two statements
    // should never overflow.
    ct_position = ct_offset_ + header_size_;
    segment_size = ct_segment_size_ - ct_position;
  }
  bool is_last_segment = (segment_nr == segment_count_ - 1);
  auto pread_status = ct_source_->PRead(ct_position, segment_size, ct_buffer);
  if (pread_status.ok() ||
      (is_last_segment && ct_buffer->size() > 0 &&
       pread_status.code() == absl::StatusCode::kOutOfRange)) {
    // some bytes were read
    auto dec_status = segment_decrypter_->DecryptSegment(
        std::vector<uint8_t>(ct_buffer->get_mem_block(),
                             ct_buffer->get_mem_block() + ct_buffer->size()),
        segment_nr, is_last_segment, pt_segment);
    if (dec_status.ok()) {
      return is_last_segment ?
          Status(util::error::OUT_OF_RANGE, "EOF") : util::OkStatus();
    }
    return dec_status;
  }
  return pread_status;
}

util::Status DecryptingRandomAccessStream::PReadAndDecrypt(
    int64_t position, int count, Buffer* dest_buffer) {
  if (position < 0 || count < 0 || dest_buffer == nullptr
      || count > dest_buffer->allocated_size() || dest_buffer->size() != 0) {
    return Status(util::error::INTERNAL,
                  "Invalid parameters to PReadAndDecrypt");
  }

  if (position > std::numeric_limits<int64_t>::max() - count) {
    return Status(
        util::error::OUT_OF_RANGE,
        absl::StrCat(
            "Invalid parameters to PReadAndDecrypt; position too large: ",
            position));
  }

  auto pt_size_result = size();
  if (pt_size_result.ok()) {
    auto pt_size = pt_size_result.ValueOrDie();
    if (position > pt_size) {
      return Status(util::error::OUT_OF_RANGE,
                    "position is larger than stream size");
    }
  }
  auto ct_buffer_result = Buffer::New(ct_segment_size_);
  if (!ct_buffer_result.ok()) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Invalid ciphertext segment size %d.",
                     ct_segment_size_);
  }
  auto ct_buffer = std::move(ct_buffer_result.ValueOrDie());
  std::vector<uint8_t> pt_segment;
  int remaining = count;
  int read_count = 0;
  int pt_offset = GetPlaintextOffset(position);
  while (remaining > 0) {
    auto segment_nr = GetSegmentNr(position + read_count);
    auto status =
        ReadAndDecryptSegment(segment_nr, ct_buffer.get(), &pt_segment);
    if (status.ok() || status.code() == absl::StatusCode::kOutOfRange) {
      int pt_count = pt_segment.size() - pt_offset;
      int to_copy_count = std::min(pt_count, remaining);
      auto s = dest_buffer->set_size(read_count + to_copy_count);
      if (!s.ok()) return s;
      std::memcpy(dest_buffer->get_mem_block() + read_count,
                  pt_segment.data() + pt_offset, to_copy_count);
      pt_offset = 0;
      if (status.code() == absl::StatusCode::kOutOfRange &&
          to_copy_count == pt_count)
        return status;
      read_count += to_copy_count;
      remaining = count - dest_buffer->size();
    } else {  // some other error happened
      return status;
    }
  }
  return util::OkStatus();
}

StatusOr<int64_t> DecryptingRandomAccessStream::size() {
  {  // Initialize, if not initialized yet.
    absl::MutexLock lock(&status_mutex_);
    InitializeIfNeeded();
    if (!status_.ok()) return status_;
  }
  return pt_size_;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
