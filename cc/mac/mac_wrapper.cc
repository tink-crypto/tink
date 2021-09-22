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

#include "tink/mac/mac_wrapper.h"

#include "absl/strings/str_cat.h"
#include "tink/crypto_format.h"
#include "tink/mac.h"
#include "tink/primitive_set.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using google::crypto::tink::OutputPrefixType;

namespace {

class MacSetWrapper : public Mac {
 public:
  explicit MacSetWrapper(std::unique_ptr<PrimitiveSet<Mac>> mac_set)
      : mac_set_(std::move(mac_set)) {}

  crypto::tink::util::StatusOr<std::string> ComputeMac(
      absl::string_view data) const override;

  crypto::tink::util::Status VerifyMac(absl::string_view mac_value,
                                       absl::string_view data) const override;

  ~MacSetWrapper() override {}

 private:
  std::unique_ptr<PrimitiveSet<Mac>> mac_set_;
};

util::Status Validate(PrimitiveSet<Mac>* mac_set) {
  if (mac_set == nullptr) {
    return util::Status(util::error::INTERNAL, "mac_set must be non-NULL");
  }
  if (mac_set->get_primary() == nullptr) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "mac_set has no primary");
  }
  return util::OkStatus();
}

util::StatusOr<std::string> MacSetWrapper::ComputeMac(
    absl::string_view data) const {
  // BoringSSL expects a non-null pointer for data,
  // regardless of whether the size is 0.
  data = subtle::SubtleUtilBoringSSL::EnsureNonNull(data);

  auto primary = mac_set_->get_primary();
  std::string local_data;
  if (primary->get_output_prefix_type() == OutputPrefixType::LEGACY) {
    local_data = std::string(data);
    local_data.append(
        reinterpret_cast<const char*>(&CryptoFormat::kLegacyStartByte), 1);
    data = local_data;
  }
  auto compute_mac_result = primary->get_primitive().ComputeMac(data);
  if (!compute_mac_result.ok()) return compute_mac_result.status();
  const std::string& key_id = primary->get_identifier();
  return key_id + compute_mac_result.ValueOrDie();
}

util::Status MacSetWrapper::VerifyMac(
    absl::string_view mac_value,
    absl::string_view data) const {
  data = subtle::SubtleUtilBoringSSL::EnsureNonNull(data);
  mac_value = subtle::SubtleUtilBoringSSL::EnsureNonNull(mac_value);

  if (mac_value.length() > CryptoFormat::kNonRawPrefixSize) {
    absl::string_view key_id =
        mac_value.substr(0, CryptoFormat::kNonRawPrefixSize);
    auto primitives_result = mac_set_->get_primitives(key_id);
    if (primitives_result.ok()) {
      absl::string_view raw_mac_value =
          mac_value.substr(CryptoFormat::kNonRawPrefixSize);
      for (auto& mac_entry : *(primitives_result.ValueOrDie())) {
        std::string legacy_data;
        absl::string_view view_on_data_or_legacy_data = data;
        if (mac_entry->get_output_prefix_type() == OutputPrefixType::LEGACY) {
          legacy_data = absl::StrCat(data, std::string("\x00", 1));
          view_on_data_or_legacy_data = legacy_data;
        }
        Mac& mac = mac_entry->get_primitive();
        util::Status status =
            mac.VerifyMac(raw_mac_value, view_on_data_or_legacy_data);
        if (status.ok()) {
          return status;
        } else {
          // TODO(przydatek): LOG that a matching key didn't verify the MAC.
        }
      }
    }
  }

  // No matching key succeeded with verification, try all RAW keys.
  auto raw_primitives_result = mac_set_->get_raw_primitives();
  if (raw_primitives_result.ok()) {
    for (auto& mac_entry : *(raw_primitives_result.ValueOrDie())) {
      Mac& mac = mac_entry->get_primitive();
      util::Status status = mac.VerifyMac(mac_value, data);
      if (status.ok()) {
        return status;
      }
    }
  }
  return util::Status(util::error::INVALID_ARGUMENT, "verification failed");
}

}  // namespace

util::StatusOr<std::unique_ptr<Mac>> MacWrapper::Wrap(
      std::unique_ptr<PrimitiveSet<Mac>> mac_set) const {
  util::Status status = Validate(mac_set.get());
  if (!status.ok()) return status;
  std::unique_ptr<Mac> mac(new MacSetWrapper(std::move(mac_set)));
  return std::move(mac);
}

}  // namespace tink
}  // namespace crypto
