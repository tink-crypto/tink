// Copyright 2020 Google LLC
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

#include "tink/aead/cord_aead_wrapper.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/cord.h"
#include "tink/aead/cord_aead.h"
#include "tink/crypto_format.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

namespace {

util::Status Validate(PrimitiveSet<CordAead>* aead_set) {
  if (aead_set == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "aead_set must be non-NULL");
  }
  if (aead_set->get_primary() == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "aead_set has no primary");
  }
  return util::OkStatus();
}

class CordAeadSetWrapper : public CordAead {
 public:
  explicit CordAeadSetWrapper(std::unique_ptr<PrimitiveSet<CordAead>> aead_set)
      : aead_set_(std::move(aead_set)) {}

  crypto::tink::util::StatusOr<absl::Cord> Encrypt(
      absl::Cord plaintext, absl::Cord associated_data) const override;

  crypto::tink::util::StatusOr<absl::Cord> Decrypt(
      absl::Cord ciphertext, absl::Cord associated_data) const override;

  ~CordAeadSetWrapper() override {}

 private:
  std::unique_ptr<PrimitiveSet<CordAead>> aead_set_;
};

util::StatusOr<absl::Cord> CordAeadSetWrapper::Encrypt(
    absl::Cord plaintext, absl::Cord associated_data) const {
  auto encrypt_result = aead_set_->get_primary()->get_primitive().Encrypt(
      plaintext, associated_data);
  if (!encrypt_result.ok()) return encrypt_result.status();
  absl::Cord result;
  result.Append(aead_set_->get_primary()->get_identifier());
  result.Append(encrypt_result.value());
  return result;
}

util::StatusOr<absl::Cord> CordAeadSetWrapper::Decrypt(
    absl::Cord ciphertext, absl::Cord associated_data) const {
  if (ciphertext.size() > CryptoFormat::kNonRawPrefixSize) {
    std::string key_id =
        std::string(ciphertext.Subcord(0, CryptoFormat::kNonRawPrefixSize));
    auto primitives_result = aead_set_->get_primitives(key_id);
    if (primitives_result.ok()) {
      auto raw_ciphertext =
          ciphertext.Subcord(key_id.size(), ciphertext.size());
      for (auto& aead_entry : *(primitives_result.value())) {
        CordAead& aead = aead_entry->get_primitive();
        auto decrypt_result = aead.Decrypt(raw_ciphertext, associated_data);
        if (decrypt_result.ok()) {
          return std::move(decrypt_result.value());
        } else {
          // LOG that a matching key didn't decrypt the ciphertext.
        }
      }
    }
  }

  // No matching key succeeded with decryption, try all RAW keys.
  auto raw_primitives_result = aead_set_->get_raw_primitives();
  if (raw_primitives_result.ok()) {
    for (auto& aead_entry : *(raw_primitives_result.value())) {
      CordAead& aead = aead_entry->get_primitive();
      auto decrypt_result = aead.Decrypt(ciphertext, associated_data);
      if (decrypt_result.ok()) {
        return std::move(decrypt_result.value());
      }
    }
  }
  return util::Status(absl::StatusCode::kInvalidArgument, "decryption failed");
}
}  // anonymous namespace

util::StatusOr<std::unique_ptr<CordAead>> CordAeadWrapper::Wrap(
    std::unique_ptr<PrimitiveSet<CordAead>> aead_set) const {
  util::Status status = Validate(aead_set.get());
  if (!status.ok()) return status;
  std::unique_ptr<CordAead> aead(new CordAeadSetWrapper(std::move(aead_set)));
  return std::move(aead);
}

}  // namespace tink
}  // namespace crypto
