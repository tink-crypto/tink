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

#include "tink/subtle/nonce_based_streaming_aead.h"

#include <utility>

#include "absl/strings/string_view.h"
#include "tink/input_stream.h"
#include "tink/output_stream.h"
#include "tink/random_access_stream.h"
#include "tink/streaming_aead.h"
#include "tink/subtle/decrypting_random_access_stream.h"
#include "tink/subtle/stream_segment_decrypter.h"
#include "tink/subtle/stream_segment_encrypter.h"
#include "tink/subtle/streaming_aead_decrypting_stream.h"
#include "tink/subtle/streaming_aead_encrypting_stream.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

crypto::tink::util::StatusOr<std::unique_ptr<crypto::tink::OutputStream>>
    NonceBasedStreamingAead::NewEncryptingStream(
        std::unique_ptr<crypto::tink::OutputStream> ciphertext_destination,
        absl::string_view associated_data) const {
  auto segment_encrypter_result = NewSegmentEncrypter(associated_data);
  if (!segment_encrypter_result.ok()) return segment_encrypter_result.status();
  return StreamingAeadEncryptingStream::New(
      std::move(segment_encrypter_result.ValueOrDie()),
      std::move(ciphertext_destination));
}

crypto::tink::util::StatusOr<std::unique_ptr<crypto::tink::InputStream>>
    NonceBasedStreamingAead::NewDecryptingStream(
        std::unique_ptr<crypto::tink::InputStream> ciphertext_source,
        absl::string_view associated_data) const {
  auto segment_decrypter_result = NewSegmentDecrypter(associated_data);
  if (!segment_decrypter_result.ok()) return segment_decrypter_result.status();
  return StreamingAeadDecryptingStream::New(
      std::move(segment_decrypter_result.ValueOrDie()),
      std::move(ciphertext_source));
}

crypto::tink::util::StatusOr<std::unique_ptr<crypto::tink::RandomAccessStream>>
    NonceBasedStreamingAead::NewDecryptingRandomAccessStream(
        std::unique_ptr<crypto::tink::RandomAccessStream> ciphertext_source,
        absl::string_view associated_data) const {
  auto segment_decrypter_result = NewSegmentDecrypter(associated_data);
  if (!segment_decrypter_result.ok()) return segment_decrypter_result.status();
  return DecryptingRandomAccessStream::New(
      std::move(segment_decrypter_result.ValueOrDie()),
      std::move(ciphertext_source));
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
