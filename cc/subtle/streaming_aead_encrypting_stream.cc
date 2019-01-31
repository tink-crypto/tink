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

#include "tink/output_stream.h"
#include "tink/subtle/stream_segment_encrypter.h"
#include "tink/util/statusor.h"

using crypto::tink::OutputStream;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;

namespace crypto {
namespace tink {
namespace subtle {

// static
StatusOr<std::unique_ptr<OutputStream>> StreamingAeadEncryptingStream::New(
    std::unique_ptr<StreamSegmentEncrypter> segment_encrypter,
    std::unique_ptr<OutputStream> ciphertext_destination) {
  return Status(util::error::UNIMPLEMENTED, "Not implemented yet");
}

StatusOr<int> StreamingAeadEncryptingStream::Next(void** data) {
  return Status(util::error::UNIMPLEMENTED, "Not implemented yet");
}

void StreamingAeadEncryptingStream::BackUp(int count) {
  // Not implemented yet.
}

Status StreamingAeadEncryptingStream::Close() {
  return Status(util::error::UNIMPLEMENTED, "Not implemented yet");
}

int64_t StreamingAeadEncryptingStream::Position() const {
  return position_;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
