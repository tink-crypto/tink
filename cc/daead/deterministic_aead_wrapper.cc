// Copyright 2018 Google Inc.
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

#include "tink/daead/deterministic_aead_wrapper.h"

#include <string>
#include <utility>

#include "absl/status/status.h"
#include "tink/crypto_format.h"
#include "tink/deterministic_aead.h"
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

constexpr absl::string_view kPrimitive = "daead";
constexpr absl::string_view kEncryptApi = "encrypt";
constexpr absl::string_view kDecryptApi = "decrypt";

util::Status Validate(PrimitiveSet<DeterministicAead>* daead_set) {
  if (daead_set == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "daead_set must be non-NULL");
  }
  if (daead_set->get_primary() == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "daead_set has no primary");
  }
  return util::OkStatus();
}

class  DeterministicAeadSetWrapper : public DeterministicAead {
 public:
  explicit DeterministicAeadSetWrapper(
      std::unique_ptr<PrimitiveSet<DeterministicAead>> daead_set,
      std::unique_ptr<MonitoringClient> monitoring_encryption_client = nullptr,
      std::unique_ptr<MonitoringClient> monitoring_decryption_client = nullptr)
      : daead_set_(std::move(daead_set)),
        monitoring_encryption_client_(std::move(monitoring_encryption_client)),
        monitoring_decryption_client_(std::move(monitoring_decryption_client))
        {}

  crypto::tink::util::StatusOr<std::string> EncryptDeterministically(
      absl::string_view plaintext,
      absl::string_view associated_data) const override;

  crypto::tink::util::StatusOr<std::string> DecryptDeterministically(
      absl::string_view ciphertext,
      absl::string_view associated_data) const override;

  ~DeterministicAeadSetWrapper() override {}

 private:
  std::unique_ptr<PrimitiveSet<DeterministicAead>> daead_set_;
  std::unique_ptr<MonitoringClient> monitoring_encryption_client_;
  std::unique_ptr<MonitoringClient> monitoring_decryption_client_;
};

util::StatusOr<std::string>
DeterministicAeadSetWrapper::EncryptDeterministically(
    absl::string_view plaintext, absl::string_view associated_data) const {
  // BoringSSL expects a non-null pointer for plaintext and associated_data,
  // regardless of whether the size is 0.
  plaintext = internal::EnsureStringNonNull(plaintext);
  associated_data = internal::EnsureStringNonNull(associated_data);

  auto encrypt_result =
      daead_set_->get_primary()->get_primitive().EncryptDeterministically(
          plaintext, associated_data);
  if (!encrypt_result.ok()) {
    if (monitoring_encryption_client_ != nullptr) {
      monitoring_encryption_client_->LogFailure();
    }
    return encrypt_result.status();
  }
  if (monitoring_encryption_client_ != nullptr) {
    monitoring_encryption_client_->Log(daead_set_->get_primary()->get_key_id(),
                                       plaintext.size());
  }
  const std::string& key_id = daead_set_->get_primary()->get_identifier();
  return key_id + encrypt_result.value();
}

util::StatusOr<std::string>
DeterministicAeadSetWrapper::DecryptDeterministically(
    absl::string_view ciphertext, absl::string_view associated_data) const {
  // BoringSSL expects a non-null pointer for plaintext and associated_data,
  // regardless of whether the size is 0.
  associated_data = internal::EnsureStringNonNull(associated_data);

  if (ciphertext.length() > CryptoFormat::kNonRawPrefixSize) {
    absl::string_view key_id =
        ciphertext.substr(0, CryptoFormat::kNonRawPrefixSize);
    auto primitives_result = daead_set_->get_primitives(key_id);
    if (primitives_result.ok()) {
      absl::string_view raw_ciphertext =
          ciphertext.substr(CryptoFormat::kNonRawPrefixSize);
      for (const auto& daead_entry : *(primitives_result.value())) {
        DeterministicAead& daead = daead_entry->get_primitive();
        auto decrypt_result =
            daead.DecryptDeterministically(raw_ciphertext, associated_data);
        if (decrypt_result.ok()) {
          if (monitoring_decryption_client_ != nullptr) {
            monitoring_decryption_client_->Log(daead_entry->get_key_id(),
                                               raw_ciphertext.size());
          }
          return std::move(decrypt_result.value());
        } else {
          // LOG that a matching key didn't decrypt the ciphertext.
        }
      }
    }
  }

  // No matching key succeeded with decryption, try all RAW keys.
  auto raw_primitives_result = daead_set_->get_raw_primitives();
  if (raw_primitives_result.ok()) {
    for (const auto& daead_entry : *(raw_primitives_result.value())) {
      DeterministicAead& daead = daead_entry->get_primitive();
      auto decrypt_result =
          daead.DecryptDeterministically(ciphertext, associated_data);
      if (decrypt_result.ok()) {
        if (monitoring_decryption_client_ != nullptr) {
          monitoring_decryption_client_->Log(daead_entry->get_key_id(),
                                             ciphertext.size());
        }
        return std::move(decrypt_result.value());
      }
    }
  }
  if (monitoring_decryption_client_ != nullptr) {
    monitoring_decryption_client_->LogFailure();
  }
  return util::Status(absl::StatusCode::kInvalidArgument, "decryption failed");
}

}  // anonymous namespace

util::StatusOr<std::unique_ptr<DeterministicAead>>
DeterministicAeadWrapper::Wrap(
    std::unique_ptr<PrimitiveSet<DeterministicAead>> primitive_set) const {
  util::Status status = Validate(primitive_set.get());
  if (!status.ok()) return status;

  MonitoringClientFactory* const monitoring_factory =
      internal::RegistryImpl::GlobalInstance().GetMonitoringClientFactory();

  // Monitoring is not enabled. Create a wrapper without monitoring clients.
  if (monitoring_factory == nullptr) {
    return {absl::make_unique<DeterministicAeadSetWrapper>(
        std::move(primitive_set))};
  }

  util::StatusOr<MonitoringKeySetInfo> keyset_info =
      internal::MonitoringKeySetInfoFromPrimitiveSet(*primitive_set);
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

  return {absl::make_unique<DeterministicAeadSetWrapper>(
      std::move(primitive_set), *std::move(monitoring_encryption_client),
      *std::move(monitoring_decryption_client))};
}

}  // namespace tink
}  // namespace crypto
