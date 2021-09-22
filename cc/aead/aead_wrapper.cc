// Copyright 2017 Google Inc.
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

#include "tink/aead/aead_wrapper.h"

#include "tink/aead.h"
#include "tink/crypto_format.h"
#include "tink/primitive_set.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

namespace {

util::Status Validate(PrimitiveSet<Aead>* aead_set) {
  if (aead_set == nullptr) {
    return util::Status(util::error::INTERNAL, "aead_set must be non-NULL");
  }
  if (aead_set->get_primary() == nullptr) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "aead_set has no primary");
  }
  return util::OkStatus();
}

class AeadSetWrapper : public Aead {
 public:
  explicit AeadSetWrapper(std::unique_ptr<PrimitiveSet<Aead>> aead_set)
      : aead_set_(std::move(aead_set)) {}

  crypto::tink::util::StatusOr<std::string> Encrypt(
      absl::string_view plaintext,
      absl::string_view associated_data) const override;

  crypto::tink::util::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext,
      absl::string_view associated_data) const override;

  ~AeadSetWrapper() override {}

 private:
  std::unique_ptr<PrimitiveSet<Aead>> aead_set_;
};

util::StatusOr<std::string> AeadSetWrapper::Encrypt(
    absl::string_view plaintext, absl::string_view associated_data) const {
  // BoringSSL expects a non-null pointer for plaintext and additional_data,
  // regardless of whether the size is 0.
  plaintext = subtle::SubtleUtilBoringSSL::EnsureNonNull(plaintext);
  associated_data = subtle::SubtleUtilBoringSSL::EnsureNonNull(associated_data);

  auto encrypt_result = aead_set_->get_primary()->get_primitive()
      .Encrypt(plaintext, associated_data);
  if (!encrypt_result.ok()) return encrypt_result.status();
  const std::string& key_id = aead_set_->get_primary()->get_identifier();
  return key_id + encrypt_result.ValueOrDie();
}

util::StatusOr<std::string> AeadSetWrapper::Decrypt(
    absl::string_view ciphertext, absl::string_view associated_data) const {
  // BoringSSL expects a non-null pointer for plaintext and additional_data,
  // regardless of whether the size is 0.
  associated_data = subtle::SubtleUtilBoringSSL::EnsureNonNull(associated_data);

  if (ciphertext.length() > CryptoFormat::kNonRawPrefixSize) {
    absl::string_view key_id =
        ciphertext.substr(0, CryptoFormat::kNonRawPrefixSize);
    auto primitives_result = aead_set_->get_primitives(key_id);
    if (primitives_result.ok()) {
      absl::string_view raw_ciphertext =
          ciphertext.substr(CryptoFormat::kNonRawPrefixSize);
      for (auto& aead_entry : *(primitives_result.ValueOrDie())) {
        Aead& aead = aead_entry->get_primitive();
        auto decrypt_result = aead.Decrypt(raw_ciphertext, associated_data);
        if (decrypt_result.ok()) {
          return std::move(decrypt_result.ValueOrDie());
        } else {
          // LOG that a matching key didn't decrypt the ciphertext.
        }
      }
    }
  }

  // No matching key succeeded with decryption, try all RAW keys.
  auto raw_primitives_result = aead_set_->get_raw_primitives();
  if (raw_primitives_result.ok()) {
    for (auto& aead_entry : *(raw_primitives_result.ValueOrDie())) {
      Aead& aead = aead_entry->get_primitive();
      auto decrypt_result = aead.Decrypt(ciphertext, associated_data);
      if (decrypt_result.ok()) {
        return std::move(decrypt_result.ValueOrDie());
      }
    }
  }
  return util::Status(util::error::INVALID_ARGUMENT, "decryption failed");
}

}  // anonymous namespace

util::StatusOr<std::unique_ptr<Aead>> AeadWrapper::Wrap(
    std::unique_ptr<PrimitiveSet<Aead>> aead_set) const {
  util::Status status = Validate(aead_set.get());
  if (!status.ok()) return status;
  std::unique_ptr<Aead> aead(new AeadSetWrapper(std::move(aead_set)));
  return std::move(aead);
}

}  // namespace tink
}  // namespace crypto
