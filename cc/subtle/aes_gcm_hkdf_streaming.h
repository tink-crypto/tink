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

#ifndef TINK_SUBTLE_AES_GCM_HKDF_STREAMING_H_
#define TINK_SUBTLE_AES_GCM_HKDF_STREAMING_H_

#include <memory>
#include <utility>

#include "tink/internal/fips_utils.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/nonce_based_streaming_aead.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

class AesGcmHkdfStreaming : public NonceBasedStreamingAead {
 public:
  struct Params {
    util::SecretData ikm;
    HashType hkdf_hash;
    int derived_key_size;
    int ciphertext_segment_size;
    int ciphertext_offset;
  };

  static util::StatusOr<std::unique_ptr<AesGcmHkdfStreaming>> New(
      Params params);

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

 protected:
  util::StatusOr<std::unique_ptr<StreamSegmentEncrypter>> NewSegmentEncrypter(
      absl::string_view associated_data) const override;

  util::StatusOr<std::unique_ptr<StreamSegmentDecrypter>> NewSegmentDecrypter(
      absl::string_view associated_data) const override;

 private:
  explicit AesGcmHkdfStreaming(Params params)
      : ikm_(std::move(params.ikm)),
        hkdf_hash_(params.hkdf_hash),
        derived_key_size_(params.derived_key_size),
        ciphertext_segment_size_(params.ciphertext_segment_size),
        ciphertext_offset_(params.ciphertext_offset) {}

  const util::SecretData ikm_;
  const HashType hkdf_hash_;
  const int derived_key_size_;
  const int ciphertext_segment_size_;
  const int ciphertext_offset_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_AES_GCM_HKDF_STREAMING_H_
