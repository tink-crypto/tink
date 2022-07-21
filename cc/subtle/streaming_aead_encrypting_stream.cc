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

#include "tink/subtle/streaming_aead_encrypting_stream.h"

#include <algorithm>
#include <cstring>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/output_stream.h"
#include "tink/subtle/stream_segment_encrypter.h"
#include "tink/util/statusor.h"

using crypto::tink::OutputStream;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;

namespace crypto {
namespace tink {
namespace subtle {

namespace {

// Writes 'contents' to the specified 'output_stream', which must be non-null.
// In case of errors returns the first non-OK status of
// output_stream->Next()-operation.

util::Status WriteToStream(const std::vector<uint8_t>& contents,
                           OutputStream* output_stream) {
  void* buffer;
  int pos = 0;
  int remaining = contents.size();
  int available_space = 0;
  int available_bytes = 0;
  while (remaining > 0) {
    auto next_result = output_stream->Next(&buffer);
    if (!next_result.ok()) return next_result.status();
    available_space = next_result.value();
    available_bytes = std::min(available_space, remaining);
    memcpy(buffer, contents.data() + pos, available_bytes);
    remaining -= available_bytes;
    pos += available_bytes;
  }
  if (available_space > available_bytes) {
    output_stream->BackUp(available_space - available_bytes);
  }
  return util::OkStatus();
}

}  // anonymous namespace

// static
StatusOr<std::unique_ptr<OutputStream>> StreamingAeadEncryptingStream::New(
    std::unique_ptr<StreamSegmentEncrypter> segment_encrypter,
    std::unique_ptr<OutputStream> ciphertext_destination) {
  if (segment_encrypter == nullptr) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "segment_encrypter must be non-null");
  }
  if (ciphertext_destination == nullptr) {
    return Status(absl::StatusCode::kInvalidArgument,
                  "cipertext_destination must be non-null");
  }
  std::unique_ptr<StreamingAeadEncryptingStream> enc_stream(
      new StreamingAeadEncryptingStream());
  enc_stream->segment_encrypter_ = std::move(segment_encrypter);
  enc_stream->ct_destination_ = std::move(ciphertext_destination);
  int first_segment_size =
      enc_stream->segment_encrypter_->get_plaintext_segment_size() -
      enc_stream->segment_encrypter_->get_ciphertext_offset() -
      enc_stream->segment_encrypter_->get_header().size();

  if (first_segment_size <= 0) {
    return Status(absl::StatusCode::kInternal,
                  "Size of the first segment must be greater than 0.");
  }
  enc_stream->pt_buffer_.resize(first_segment_size);
  enc_stream->pt_to_encrypt_.resize(0);
  enc_stream->position_ = 0;
  enc_stream->is_first_segment_ = true;
  enc_stream->count_backedup_ = first_segment_size;
  enc_stream->pt_buffer_offset_ = 0;
  enc_stream->status_ = util::OkStatus();
  return {std::move(enc_stream)};
}

StatusOr<int> StreamingAeadEncryptingStream::Next(void** data) {
  if (!status_.ok()) return status_;

  // The first call to Next().
  if (is_first_segment_) {
    is_first_segment_ = false;
    count_backedup_ = 0;
    status_ =
        WriteToStream(segment_encrypter_->get_header(), ct_destination_.get());
    if (!status_.ok()) return status_;
    *data = pt_buffer_.data();
    position_ = pt_buffer_.size();
    return pt_buffer_.size();
  }

  // If some space was backed up, return it first.
  if (count_backedup_ > 0) {
    position_ += count_backedup_;
    pt_buffer_offset_ = pt_buffer_.size() - count_backedup_;
    int backedup = count_backedup_;
    count_backedup_ = 0;
    *data = pt_buffer_.data() + pt_buffer_offset_;
    return backedup;
  }

  // We're past the first segment, and no space was backed up, so we:
  // 1. encrypt pt_to_encrypt_ (if non-empty) as a not-last segment
  //    and attempt to write the ciphertext to ct_destination_.
  // 2. move contents of pt_buffer_ to pt_to_encrypt_ (for later encryption,
  //    as we don't know yet whether it will be the last segment or not.
  // 3. prepare and return "fresh" pt_buffer_.
  //
  // Step 1.
  if (!pt_to_encrypt_.empty()) {
    status_ = segment_encrypter_->EncryptSegment(
        pt_to_encrypt_, /* is_last_segment = */ false, &ct_buffer_);
    if (!status_.ok()) return status_;
    status_ = WriteToStream(ct_buffer_, ct_destination_.get());
    if (!status_.ok()) return status_;
  }
  // Step 2.
  pt_buffer_.swap(pt_to_encrypt_);
  // Step 3.
  pt_buffer_.resize(segment_encrypter_->get_plaintext_segment_size());
  *data = pt_buffer_.data();
  pt_buffer_offset_ = 0;
  position_ += pt_buffer_.size();
  return pt_buffer_.size();
}

void StreamingAeadEncryptingStream::BackUp(int count) {
  if (is_first_segment_ || !status_.ok() || count < 1) return;
  int curr_buffer_size = pt_buffer_.size() - pt_buffer_offset_;
  int actual_count = std::min(count, curr_buffer_size - count_backedup_);
  count_backedup_ += actual_count;
  position_ -= actual_count;
}

Status StreamingAeadEncryptingStream::Close() {
  if (!status_.ok()) return status_;
  if (is_first_segment_) {  // Next() was never called.
    status_ =
        WriteToStream(segment_encrypter_->get_header(), ct_destination_.get());
    if (!status_.ok()) return status_;
  }

  // The last segment encrypts plaintext from pt_to_encrypt_,
  // unless the current pt_buffer_ has some plaintext bytes.
  std::vector<uint8_t>* pt_last_segment = &pt_to_encrypt_;
  if ((!pt_buffer_.empty()) && count_backedup_ < pt_buffer_.size()) {
    // The last segment encrypts plaintext from pt_buffer_.
    pt_buffer_.resize(pt_buffer_.size() - count_backedup_);
    pt_last_segment = &pt_buffer_;
  }
  if (pt_last_segment != &pt_to_encrypt_ && (!pt_to_encrypt_.empty())) {
    // Before writing the last segment we must encrypt pt_to_encrypt_.
    status_ = segment_encrypter_->EncryptSegment(
        pt_to_encrypt_, /* is_last_segment = */ false, &ct_buffer_);
    if (!status_.ok()) {
      ct_destination_->Close().IgnoreError();
      return status_;
    }
    status_ = WriteToStream(ct_buffer_, ct_destination_.get());
    if (!status_.ok()) {
      ct_destination_->Close().IgnoreError();
      return status_;
    }
  }

  // Encrypt pt_last_segment, write the ciphertext, and close the stream.
  status_ = segment_encrypter_->EncryptSegment(
      *pt_last_segment, /* is_last_segment = */ true, &ct_buffer_);
  if (!status_.ok()) {
    ct_destination_->Close().IgnoreError();
    return status_;
  }
  status_ = WriteToStream(ct_buffer_, ct_destination_.get());
  if (!status_.ok()) {
    ct_destination_->Close().IgnoreError();
    return status_;
  }
  status_ = Status(absl::StatusCode::kFailedPrecondition, "Stream closed");
  return ct_destination_->Close();
}

int64_t StreamingAeadEncryptingStream::Position() const { return position_; }

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
