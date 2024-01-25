// Copyright 2023 Google LLC
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

#ifndef TINK_AEAD_AES_GCM_SIV_KEY_H_
#define TINK_AEAD_AES_GCM_SIV_KEY_H_

#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aead_key.h"
#include "tink/aead/aes_gcm_siv_parameters.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Represents an AEAD that uses AES-GCM-SIV.
class AesGcmSivKey : public AeadKey {
 public:
  // Copyable and movable.
  AesGcmSivKey(const AesGcmSivKey& other) = default;
  AesGcmSivKey& operator=(const AesGcmSivKey& other) = default;
  AesGcmSivKey(AesGcmSivKey&& other) = default;
  AesGcmSivKey& operator=(AesGcmSivKey&& other) = default;

  // Creates a new AES-GCM-SIV key.  If the parameters specify a variant
  // that uses a prefix, then the id is used to compute this prefix.
  static util::StatusOr<AesGcmSivKey> Create(
      const AesGcmSivParameters& parameters, const RestrictedData& key_bytes,
      absl::optional<int> id_requirement, PartialKeyAccessToken token);

  // Returns the underlying AES key.
  const RestrictedData& GetKeyBytes(PartialKeyAccessToken token) const {
    return key_bytes_;
  }

  absl::string_view GetOutputPrefix() const override { return output_prefix_; }

  const AesGcmSivParameters& GetParameters() const override {
    return parameters_;
  }

  absl::optional<int> GetIdRequirement() const override {
    return id_requirement_;
  }

  bool operator==(const Key& other) const override;

 private:
  AesGcmSivKey(const AesGcmSivParameters& parameters,
               const RestrictedData& key_bytes,
               absl::optional<int> id_requirement, std::string output_prefix)
      : parameters_(parameters),
        key_bytes_(key_bytes),
        id_requirement_(id_requirement),
        output_prefix_(std::move(output_prefix)) {}

  AesGcmSivParameters parameters_;
  RestrictedData key_bytes_;
  absl::optional<int> id_requirement_;
  std::string output_prefix_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_AES_GCM_SIV_KEY_H_
