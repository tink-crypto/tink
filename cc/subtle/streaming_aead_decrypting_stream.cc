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

#include "tink/subtle/streaming_aead_decrypting_stream.h"

#include <algorithm>
#include <cstring>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/input_stream.h"
#include "tink/subtle/stream_segment_decrypter.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

using crypto::tink::InputStream;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;

namespace crypto {
namespace tink {
namespace subtle {

namespace {

// Reads at most 'count' bytes from the specified 'input_stream',
// and puts them into 'output', where both 'input_stream' and 'output'
// must be non-null.
// Will try to read exactly 'count' bytes, unless the end of stream
// is reached (then returns status OUT_OF_RANGE) or an error occurs
// (an other non-OK status).
// Before returning, resizes 'output' accordingly, to reflect
// the actual number of bytes read.

util::Status ReadFromStream(InputStream* input_stream, int count,
                            std::vector<uint8_t>* output) {
  if (count <= 0 || input_stream == nullptr || output == nullptr) {
    return Status(absl::StatusCode::kInternal, "Illegal read from a stream");
  }
  const void* buffer;
  int bytes_to_be_read = count;
  int read_bytes;    // bytes read in one Next()-call
  int needed_bytes;  // bytes actually needed
  output->resize(count);
  while (bytes_to_be_read > 0) {
    auto next_result = input_stream->Next(&buffer);
    if (next_result.status().code() == absl::StatusCode::kOutOfRange) {
      // End of stream.
      output->resize(count - bytes_to_be_read);
      return next_result.status();
    }
    if (!next_result.ok()) return next_result.status();
    read_bytes = next_result.value();
    needed_bytes = std::min(read_bytes, bytes_to_be_read);
    memcpy(output->data() + (count - bytes_to_be_read), buffer, needed_bytes);
    bytes_to_be_read -= needed_bytes;
  }
  if (read_bytes > needed_bytes) {
    input_stream->BackUp(read_bytes - needed_bytes);
  }
  return util::OkStatus();
}

}  // anonymous namespace

// static
StatusOr<std::unique_ptr<InputStream>> StreamingAeadDecryptingStream::New(
    std::unique_ptr<StreamSegmentDecrypter> segment_decrypter,
    std::unique_ptr<InputStream> ciphertext_source) {
  if (segment_decrypter == nullptr) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "segment_decrypter must be non-null");
  }
  if (ciphertext_source == nullptr) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "cipertext_source must be non-null");
  }
  std::unique_ptr<StreamingAeadDecryptingStream> dec_stream(
      new StreamingAeadDecryptingStream());
  dec_stream->segment_decrypter_ = std::move(segment_decrypter);
  dec_stream->ct_source_ = std::move(ciphertext_source);
  int first_segment_size =
      dec_stream->segment_decrypter_->get_ciphertext_segment_size() -
      dec_stream->segment_decrypter_->get_ciphertext_offset() -
      dec_stream->segment_decrypter_->get_header_size();
  if (first_segment_size <= 0) {
    return Status(absl::StatusCode::kInternal,
                  "Size of the first segment must be greater than 0.");
  }
  dec_stream->ct_buffer_.resize(first_segment_size);
  dec_stream->position_ = 0;
  dec_stream->segment_number_ = 0;
  dec_stream->is_initialized_ = false;
  dec_stream->read_last_segment_ = false;
  dec_stream->count_backedup_ = first_segment_size;
  dec_stream->pt_buffer_offset_ = 0;
  dec_stream->status_ = util::OkStatus();
  return {std::move(dec_stream)};
}

StatusOr<int> StreamingAeadDecryptingStream::Next(const void** data) {
  if (!status_.ok()) return status_;

  // The first call to Next().
  if (!is_initialized_) {
    std::vector<uint8_t> header;
    status_ = ReadFromStream(ct_source_.get(),
                             segment_decrypter_->get_header_size(), &header);
    if (status_.code() == absl::StatusCode::kOutOfRange) {
      status_ = Status(absl::StatusCode::kInvalidArgument,
                       "Could not read stream header.");
    }
    if (!status_.ok()) return status_;
    status_ = segment_decrypter_->Init(header);
    if (!status_.ok()) return status_;
    is_initialized_ = true;
    count_backedup_ = 0;
    status_ = ReadFromStream(ct_source_.get(), ct_buffer_.size(), &ct_buffer_);
    if (!status_.ok() && (status_.code() != absl::StatusCode::kOutOfRange)) {
      return status_;
    }
    read_last_segment_ = (status_.code() == absl::StatusCode::kOutOfRange);
    status_ = segment_decrypter_->DecryptSegment(
        ct_buffer_,
        /* segment_number = */ segment_number_,
        /* is_last_segment = */ read_last_segment_,
        &pt_buffer_);
    if (!status_.ok() && !read_last_segment_) {
      // Try decrypting as the last segment, if haven't tried yet.
      read_last_segment_ = true;
      status_ = segment_decrypter_->DecryptSegment(
          ct_buffer_,
          /* segment_number = */ segment_number_,
          /* is_last_segment = */ read_last_segment_,
          &pt_buffer_);
    }
    if (!status_.ok()) return status_;
    *data = pt_buffer_.data();
    position_ = pt_buffer_.size();
    return pt_buffer_.size();
  }

  // If some bytes were backed up, return them first.
  if (count_backedup_ > 0) {
    position_ += count_backedup_;
    pt_buffer_offset_ = pt_buffer_.size() - count_backedup_;
    int backedup = count_backedup_;
    count_backedup_ = 0;
    *data = pt_buffer_.data() + pt_buffer_offset_;
    return backedup;
  }

  // We're past the first segment, and no space was backed up, so we
  // try to get and decrypt the next ciphertext segment, if any.
  if (read_last_segment_) {
    status_ = Status(absl::StatusCode::kOutOfRange, "Reached end of stream.");
    return status_;
  }
  segment_number_++;
  ct_buffer_.resize(segment_decrypter_->get_ciphertext_segment_size());
  status_ = ReadFromStream(ct_source_.get(), ct_buffer_.size(), &ct_buffer_);
  if (!status_.ok() && (status_.code() != absl::StatusCode::kOutOfRange)) {
    return status_;
  }
  read_last_segment_ = (status_.code() == absl::StatusCode::kOutOfRange);
  status_ = segment_decrypter_->DecryptSegment(
      ct_buffer_,
      /* segment_number = */ segment_number_,
      /* is_last_segment = */ read_last_segment_,
      &pt_buffer_);
  if (!status_.ok() && !read_last_segment_) {
    // Try decrypting as the last segment, if haven't tried yet.
    read_last_segment_ = true;
    status_ = segment_decrypter_->DecryptSegment(
        ct_buffer_,
        /* segment_number = */ segment_number_,
        /* is_last_segment = */ read_last_segment_,
        &pt_buffer_);
  }
  if (!status_.ok()) return status_;
  *data = pt_buffer_.data();
  pt_buffer_offset_ = 0;
  position_ += pt_buffer_.size();
  return pt_buffer_.size();
}

void StreamingAeadDecryptingStream::BackUp(int count) {
  if (!is_initialized_ || !status_.ok() || count < 1) return;
  int curr_buffer_size = pt_buffer_.size() - pt_buffer_offset_;
  int actual_count = std::min(count, curr_buffer_size - count_backedup_);
  count_backedup_ += actual_count;
  position_ -= actual_count;
}

int64_t StreamingAeadDecryptingStream::Position() const {
  return position_;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
