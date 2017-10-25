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

#include "cc/aead/aead_set_wrapper.h"

#include "cc/aead.h"
#include "cc/crypto_format.h"
#include "cc/primitive_set.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"

namespace util = crypto::tink::util;

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
  return util::Status::OK;
}

}  // anonymous namespace

// static
util::StatusOr<std::unique_ptr<Aead>> AeadSetWrapper::NewAead(
    std::unique_ptr<PrimitiveSet<Aead>> aead_set) {
  util::Status status = Validate(aead_set.get());
  if (!status.ok()) return status;
  std::unique_ptr<Aead> aead(new AeadSetWrapper(std::move(aead_set)));
  return std::move(aead);
}

util::StatusOr<std::string> AeadSetWrapper::Encrypt(
    absl::string_view plaintext,
    absl::string_view associated_data) const {
  auto encrypt_result = aead_set_->get_primary()->get_primitive()
      .Encrypt(plaintext, associated_data);
  if (!encrypt_result.ok()) return encrypt_result.status();
  const std::string& key_id = aead_set_->get_primary()->get_identifier();
  return key_id + encrypt_result.ValueOrDie();
}

util::StatusOr<std::string> AeadSetWrapper::Decrypt(
    absl::string_view ciphertext,
    absl::string_view associated_data) const {
  if (ciphertext.length() > CryptoFormat::kNonRawPrefixSize) {
    const std::string& key_id = std::string(
        ciphertext.substr(0, CryptoFormat::kNonRawPrefixSize));
    auto primitives_result = aead_set_->get_primitives(key_id);
    if (primitives_result.ok()) {
      absl::string_view raw_ciphertext =
          ciphertext.substr(CryptoFormat::kNonRawPrefixSize);
      for (auto& aead_entry : *(primitives_result.ValueOrDie())) {
        Aead& aead = aead_entry.get_primitive();
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
      Aead& aead = aead_entry.get_primitive();
      auto decrypt_result = aead.Decrypt(ciphertext, associated_data);
      if (decrypt_result.ok()) {
        return std::move(decrypt_result.ValueOrDie());
      }
    }
  }
  return util::Status(util::error::INVALID_ARGUMENT, "decryption failed");
}

}  // namespace tink
}  // namespace crypto
