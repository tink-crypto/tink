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

#ifndef TINK_SUBTLE_NONCE_BASED_STREAMING_AEAD_H_
#define TINK_SUBTLE_NONCE_BASED_STREAMING_AEAD_H_

#include <memory>

#include "absl/strings/string_view.h"
#include "tink/input_stream.h"
#include "tink/output_stream.h"
#include "tink/random_access_stream.h"
#include "tink/streaming_aead.h"
#include "tink/subtle/stream_segment_decrypter.h"
#include "tink/subtle/stream_segment_encrypter.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// An abstract class for StreamingAead using the nonce based online encryption
// scheme proposed in "Online Authenticated-Encryption and its Nonce-Reuse
// Misuse-Resistance" by Hoang, Reyhanitabar, Rogaway and Vizár
// (https://eprint.iacr.org/2015/189.pdf)
class NonceBasedStreamingAead : public StreamingAead {
 public:
  // Methods of StreamingAead-interface implemented by this class.
  crypto::tink::util::StatusOr<std::unique_ptr<crypto::tink::OutputStream>>
  NewEncryptingStream(
      std::unique_ptr<crypto::tink::OutputStream> ciphertext_destination,
      absl::string_view associated_data) const override;

  crypto::tink::util::StatusOr<std::unique_ptr<crypto::tink::InputStream>>
  NewDecryptingStream(
      std::unique_ptr<crypto::tink::InputStream> ciphertext_source,
      absl::string_view associated_data) const override;

  crypto::tink::util::StatusOr<
      std::unique_ptr<crypto::tink::RandomAccessStream>>
  NewDecryptingRandomAccessStream(
      std::unique_ptr<crypto::tink::RandomAccessStream> ciphertext_source,
      absl::string_view associated_data) const override;

 protected:
  // Methods to be implemented by a subclass of this class.

  // Returns a new StreamSegmentEncrypter that uses `associated_data` for AEAD.
  virtual crypto::tink::util::StatusOr<std::unique_ptr<StreamSegmentEncrypter>>
  NewSegmentEncrypter(absl::string_view associated_data) const = 0;

  // Returns a new StreamSegmentDecrypter that uses `associated_data` for AEAD.
  virtual crypto::tink::util::StatusOr<std::unique_ptr<StreamSegmentDecrypter>>
  NewSegmentDecrypter(absl::string_view associated_data) const = 0;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_NONCE_BASED_STREAMING_AEAD_H_
