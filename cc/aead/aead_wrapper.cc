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

#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/crypto_format.h"
#include "tink/internal/monitoring_util.h"
#include "tink/internal/registry_impl.h"
#include "tink/internal/util.h"
#include "tink/monitoring/monitoring.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace {

constexpr absl::string_view kPrimitive = "aead";
constexpr absl::string_view kEncryptApi = "encrypt";
constexpr absl::string_view kDecryptApi = "decrypt";

util::Status Validate(PrimitiveSet<Aead>* aead_set) {
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

// The actual wrapper.
class AeadSetWrapper : public Aead {
 public:
  explicit AeadSetWrapper(
      std::unique_ptr<PrimitiveSet<Aead>> aead_set,
      std::unique_ptr<MonitoringClient> monitoring_encryption_client = nullptr,
      std::unique_ptr<MonitoringClient> monitoring_decryption_client = nullptr)
      : aead_set_(std::move(aead_set)),
        monitoring_encryption_client_(std::move(monitoring_encryption_client)),
        monitoring_decryption_client_(std::move(monitoring_decryption_client)) {
  }

  util::StatusOr<std::string> Encrypt(
      absl::string_view plaintext,
      absl::string_view associated_data) const override;

  util::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext,
      absl::string_view associated_data) const override;

 private:
  std::unique_ptr<PrimitiveSet<Aead>> aead_set_;
  std::unique_ptr<MonitoringClient> monitoring_encryption_client_;
  std::unique_ptr<MonitoringClient> monitoring_decryption_client_;
};

util::StatusOr<std::string> AeadSetWrapper::Encrypt(
    absl::string_view plaintext, absl::string_view associated_data) const {
  associated_data = internal::EnsureStringNonNull(associated_data);
  const Aead& primitive = aead_set_->get_primary()->get_primitive();
  util::StatusOr<std::string> ciphertext =
      primitive.Encrypt(plaintext, associated_data);
  if (!ciphertext.ok()) {
    if (monitoring_encryption_client_ != nullptr) {
      monitoring_encryption_client_->LogFailure();
    }
    return ciphertext.status();
  }
  if (monitoring_encryption_client_ != nullptr) {
    monitoring_encryption_client_->Log(aead_set_->get_primary()->get_key_id(),
                                       plaintext.size());
  }
  const std::string& key_id = aead_set_->get_primary()->get_identifier();
  return absl::StrCat(key_id, *ciphertext);
}

util::StatusOr<std::string> AeadSetWrapper::Decrypt(
    absl::string_view ciphertext, absl::string_view associated_data) const {
  // BoringSSL expects a non-null pointer for plaintext and additional_data,
  // regardless of whether the size is 0.
  associated_data = internal::EnsureStringNonNull(associated_data);

  if (ciphertext.length() > CryptoFormat::kNonRawPrefixSize) {
    absl::string_view key_id =
        ciphertext.substr(0, CryptoFormat::kNonRawPrefixSize);
    util::StatusOr<const PrimitiveSet<Aead>::Primitives*> primitives =
        aead_set_->get_primitives(key_id);
    if (primitives.ok()) {
      absl::string_view raw_ciphertext =
          ciphertext.substr(CryptoFormat::kNonRawPrefixSize);
      for (const std::unique_ptr<PrimitiveSet<Aead>::Entry<Aead>>& aead_entry :
           **primitives) {
        Aead& aead = aead_entry->get_primitive();
        util::StatusOr<std::string> plaintext =
            aead.Decrypt(raw_ciphertext, associated_data);
        if (plaintext.ok()) {
          if (monitoring_decryption_client_ != nullptr) {
            monitoring_decryption_client_->Log(aead_entry->get_key_id(),
                                               raw_ciphertext.size());
          }
          return plaintext;
        }
      }
    }
  }

  // No matching key succeeded with decryption, try all RAW keys.
  util::StatusOr<const PrimitiveSet<Aead>::Primitives*> raw_primitives =
      aead_set_->get_raw_primitives();
  if (raw_primitives.ok()) {
    for (const std::unique_ptr<PrimitiveSet<Aead>::Entry<Aead>>& aead_entry :
         **raw_primitives) {
      Aead& aead = aead_entry->get_primitive();
      util::StatusOr<std::string> plaintext =
          aead.Decrypt(ciphertext, associated_data);
      if (plaintext.ok()) {
        if (monitoring_decryption_client_ != nullptr) {
          monitoring_decryption_client_->Log(aead_entry->get_key_id(),
                                             ciphertext.size());
        }
        return plaintext;
      }
    }
  }
  if (monitoring_decryption_client_ != nullptr) {
    monitoring_decryption_client_->LogFailure();
  }
  return util::Status(absl::StatusCode::kInvalidArgument, "decryption failed");
}

}  // namespace

util::StatusOr<std::unique_ptr<Aead>> AeadWrapper::Wrap(
    std::unique_ptr<PrimitiveSet<Aead>> aead_set) const {
  util::Status status = Validate(aead_set.get());
  if (!status.ok()) {
    return status;
  }

  MonitoringClientFactory* const monitoring_factory =
      internal::RegistryImpl::GlobalInstance().GetMonitoringClientFactory();

  // Monitoring is not enabled. Create a wrapper without monitoring clients.
  if (monitoring_factory == nullptr) {
    return {absl::make_unique<AeadSetWrapper>(std::move(aead_set))};
  }

  util::StatusOr<MonitoringKeySetInfo> keyset_info =
      internal::MonitoringKeySetInfoFromPrimitiveSet(*aead_set);
  if (!keyset_info.ok()) {
    return keyset_info.status();
  }

  util::StatusOr<std::unique_ptr<MonitoringClient>>
      monitoring_encryption_client = monitoring_factory->New(
          MonitoringContext(kPrimitive, kEncryptApi, *keyset_info));
  if (!monitoring_encryption_client.ok()) {
    return monitoring_encryption_client.status();
  }

  util::StatusOr<std::unique_ptr<MonitoringClient>>
      monitoring_decryption_client = monitoring_factory->New(
          MonitoringContext(kPrimitive, kDecryptApi, *keyset_info));
  if (!monitoring_decryption_client.ok()) {
    return monitoring_decryption_client.status();
  }

  return {absl::make_unique<AeadSetWrapper>(
      std::move(aead_set), *std::move(monitoring_encryption_client),
      *std::move(monitoring_decryption_client))};
}

}  // namespace tink
}  // namespace crypto
