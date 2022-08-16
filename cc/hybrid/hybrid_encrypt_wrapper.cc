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

#include "tink/hybrid/hybrid_encrypt_wrapper.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "tink/crypto_format.h"
#include "tink/hybrid_encrypt.h"
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

constexpr absl::string_view kPrimitive = "hybrid_encrypt";
constexpr absl::string_view kEncryptApi = "encrypt";

util::Status Validate(PrimitiveSet<HybridEncrypt>* hybrid_encrypt_set) {
  if (hybrid_encrypt_set == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "hybrid_encrypt_set must be non-NULL");
  }
  if (hybrid_encrypt_set->get_primary() == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "hybrid_encrypt_set has no primary");
  }
  return util::OkStatus();
}

// Returns an HybridEncrypt-primitive that uses the primary
// HybridEncrypt-instance provided in 'hybrid_encrypt_set',
// which must be non-NULL (and must contain a primary instance).
class HybridEncryptSetWrapper : public HybridEncrypt {
 public:
  explicit HybridEncryptSetWrapper(
      std::unique_ptr<PrimitiveSet<HybridEncrypt>> hybrid_encrypt_set,
      std::unique_ptr<MonitoringClient> monitoring_encryption_client = nullptr)
      : hybrid_encrypt_set_(std::move(hybrid_encrypt_set)),
        monitoring_encryption_client_(std::move(monitoring_encryption_client)) {
  }

  crypto::tink::util::StatusOr<std::string> Encrypt(
      absl::string_view plaintext,
      absl::string_view context_info) const override;

  ~HybridEncryptSetWrapper() override {}

 private:
  std::unique_ptr<PrimitiveSet<HybridEncrypt>> hybrid_encrypt_set_;
  std::unique_ptr<MonitoringClient> monitoring_encryption_client_;
};

util::StatusOr<std::string> HybridEncryptSetWrapper::Encrypt(
    absl::string_view plaintext, absl::string_view context_info) const {
  // BoringSSL expects a non-null pointer for plaintext and context_info,
  // regardless of whether the size is 0.
  plaintext = internal::EnsureStringNonNull(plaintext);
  context_info = internal::EnsureStringNonNull(context_info);

  auto primary = hybrid_encrypt_set_->get_primary();
  auto encrypt_result =
      primary->get_primitive().Encrypt(plaintext, context_info);
  if (!encrypt_result.ok()) {
    if (monitoring_encryption_client_ != nullptr) {
      monitoring_encryption_client_->LogFailure();
    }
    return encrypt_result.status();
  }
  if (monitoring_encryption_client_ != nullptr) {
    monitoring_encryption_client_->Log(
        hybrid_encrypt_set_->get_primary()->get_key_id(), plaintext.size());
  }
  const std::string& key_id = primary->get_identifier();
  return key_id + encrypt_result.value();
}

}  // anonymous namespace

util::StatusOr<std::unique_ptr<HybridEncrypt>> HybridEncryptWrapper::Wrap(
    std::unique_ptr<PrimitiveSet<HybridEncrypt>> primitive_set) const {
  util::Status status = Validate(primitive_set.get());
  if (!status.ok()) return status;

  MonitoringClientFactory* const monitoring_factory =
      internal::RegistryImpl::GlobalInstance().GetMonitoringClientFactory();

  // Monitoring is not enabled. Create a wrapper without monitoring clients.
  if (monitoring_factory == nullptr) {
    return {
        absl::make_unique<HybridEncryptSetWrapper>(std::move(primitive_set))};
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

  return {absl::make_unique<HybridEncryptSetWrapper>(
      std::move(primitive_set), *std::move(monitoring_encryption_client))};
}

}  // namespace tink
}  // namespace crypto
