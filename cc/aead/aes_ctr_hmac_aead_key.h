// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_AEAD_AES_CTR_HMAC_AEAD_KEY_H_
#define TINK_AEAD_AES_CTR_HMAC_AEAD_KEY_H_

#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aead_key.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Represents an AEAD that uses AES-CTR_HMAC.
class AesCtrHmacAeadKey : public AeadKey {
 public:
  // Copyable and movable.
  AesCtrHmacAeadKey(const AesCtrHmacAeadKey& other) = default;
  AesCtrHmacAeadKey& operator=(const AesCtrHmacAeadKey& other) = default;
  AesCtrHmacAeadKey(AesCtrHmacAeadKey&& other) = default;
  AesCtrHmacAeadKey& operator=(AesCtrHmacAeadKey&& other) = default;

  // Creates an AES-CTR-HMAC-AEAD key instance.
  class Builder {
   public:
    // Copyable and movable.
    Builder(const Builder& other) = default;
    Builder& operator=(const Builder& other) = default;
    Builder(Builder&& other) = default;
    Builder& operator=(Builder&& other) = default;

    // Creates initially empty private key builder.
    Builder() = default;

    Builder& SetParameters(const AesCtrHmacAeadParameters& parameters);
    Builder& SetAesKeyBytes(const RestrictedData& aes_key_bytes);
    Builder& SetHmacKeyBytes(const RestrictedData& hmac_key_bytes);
    Builder& SetIdRequirement(absl::optional<int> id_requirement);

    // Creates an AES-CTR-HMAC-AEAD key object from this builder.
    util::StatusOr<AesCtrHmacAeadKey> Build(PartialKeyAccessToken token);

   private:
    absl::optional<AesCtrHmacAeadParameters> parameters_;
    absl::optional<RestrictedData> aes_key_bytes_;
    absl::optional<RestrictedData> hmac_key_bytes_;
    absl::optional<int> id_requirement_;
  };

  // Returns the underlying AES key bytes.
  const RestrictedData& GetAesKeyBytes(PartialKeyAccessToken token) const {
    return aes_key_bytes_;
  }

  // Returns the underlying HMAC key bytes.
  const RestrictedData& GetHmacKeyBytes(PartialKeyAccessToken token) const {
    return hmac_key_bytes_;
  }

  absl::string_view GetOutputPrefix() const override { return output_prefix_; }

  const AesCtrHmacAeadParameters& GetParameters() const override {
    return parameters_;
  }

  absl::optional<int> GetIdRequirement() const override {
    return id_requirement_;
  }

  bool operator==(const Key& other) const override;

 private:
  AesCtrHmacAeadKey(const AesCtrHmacAeadParameters& parameters,
                    const RestrictedData& aes_key_bytes,
                    const RestrictedData& hmac_key_bytes,
                    absl::optional<int> id_requirement,
                    std::string output_prefix)
      : parameters_(parameters),
        aes_key_bytes_(aes_key_bytes),
        hmac_key_bytes_(hmac_key_bytes),
        id_requirement_(id_requirement),
        output_prefix_(std::move(output_prefix)) {}

  AesCtrHmacAeadParameters parameters_;
  RestrictedData aes_key_bytes_;
  RestrictedData hmac_key_bytes_;
  absl::optional<int> id_requirement_;
  std::string output_prefix_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_AES_CTR_HMAC_AEAD_KEY_H_
