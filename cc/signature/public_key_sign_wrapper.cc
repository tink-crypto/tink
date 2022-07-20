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

#include "tink/signature/public_key_sign_wrapper.h"

#include <string>
#include <utility>

#include "absl/status/status.h"
#include "tink/crypto_format.h"
#include "tink/internal/monitoring_util.h"
#include "tink/internal/registry_impl.h"
#include "tink/internal/util.h"
#include "tink/monitoring/monitoring.h"
#include "tink/primitive_set.h"
#include "tink/public_key_sign.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using google::crypto::tink::OutputPrefixType;

namespace {

constexpr absl::string_view kPrimitive = "public_key_sign";
constexpr absl::string_view kSignApi = "sign";

util::Status Validate(PrimitiveSet<PublicKeySign>* public_key_sign_set) {
  if (public_key_sign_set == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "public_key_sign_set must be non-NULL");
  }
  if (public_key_sign_set->get_primary() == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "public_key_sign_set has no primary");
  }
  return util::OkStatus();
}

class PublicKeySignSetWrapper : public PublicKeySign {
 public:
  explicit PublicKeySignSetWrapper(
      std::unique_ptr<PrimitiveSet<PublicKeySign>> public_key_sign_set,
      std::unique_ptr<MonitoringClient> monitoring_sign_client = nullptr)
      : public_key_sign_set_(std::move(public_key_sign_set)),
        monitoring_sign_client_(std::move(monitoring_sign_client)) {}

  crypto::tink::util::StatusOr<std::string> Sign(
      absl::string_view data) const override;

  ~PublicKeySignSetWrapper() override {}

 private:
  std::unique_ptr<PrimitiveSet<PublicKeySign>> public_key_sign_set_;
  std::unique_ptr<MonitoringClient> monitoring_sign_client_;
};

util::StatusOr<std::string> PublicKeySignSetWrapper::Sign(
    absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = internal::EnsureStringNonNull(data);

  auto primary = public_key_sign_set_->get_primary();
  std::string local_data;
  if (primary->get_output_prefix_type() == OutputPrefixType::LEGACY) {
    local_data = std::string(data);
    local_data.append(1, CryptoFormat::kLegacyStartByte);
    data = local_data;
  }
  auto sign_result = primary->get_primitive().Sign(data);
  if (!sign_result.ok()) {
    if (monitoring_sign_client_ != nullptr) {
      monitoring_sign_client_->LogFailure();
    }
    return sign_result.status();
  }
  if (monitoring_sign_client_ != nullptr) {
    monitoring_sign_client_->Log(
        public_key_sign_set_->get_primary()->get_key_id(), data.size());
  }
  const std::string& key_id = primary->get_identifier();
  return key_id + sign_result.value();
}

}  // anonymous namespace

util::StatusOr<std::unique_ptr<PublicKeySign>> PublicKeySignWrapper::Wrap(
    std::unique_ptr<PrimitiveSet<PublicKeySign>> primitive_set) const {
  util::Status status = Validate(primitive_set.get());
  if (!status.ok()) return status;

  MonitoringClientFactory* const monitoring_factory =
      internal::RegistryImpl::GlobalInstance().GetMonitoringClientFactory();

  // Monitoring is not enabled. Create a wrapper without monitoring clients.
  if (monitoring_factory == nullptr) {
    return {
        absl::make_unique<PublicKeySignSetWrapper>(std::move(primitive_set))};
  }

  util::StatusOr<MonitoringKeySetInfo> keyset_info =
      internal::MonitoringKeySetInfoFromPrimitiveSet(*primitive_set);
  if (!keyset_info.ok()) {
    return keyset_info.status();
  }

  util::StatusOr<std::unique_ptr<MonitoringClient>> monitoring_sign_client =
      monitoring_factory->New(
          MonitoringContext(kPrimitive, kSignApi, *keyset_info));
  if (!monitoring_sign_client.ok()) {
    return monitoring_sign_client.status();
  }

  return {absl::make_unique<PublicKeySignSetWrapper>(
      std::move(primitive_set), *std::move(monitoring_sign_client))};
}

}  // namespace tink
}  // namespace crypto
