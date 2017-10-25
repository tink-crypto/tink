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

#include "cc/mac/mac_set_wrapper.h"

#include "cc/mac.h"
#include "cc/crypto_format.h"
#include "cc/primitive_set.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"

namespace util = crypto::tink::util;

namespace crypto {
namespace tink {

namespace {

util::Status Validate(PrimitiveSet<Mac>* mac_set) {
  if (mac_set == nullptr) {
    return util::Status(util::error::INTERNAL, "mac_set must be non-NULL");
  }
  if (mac_set->get_primary() == nullptr) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "mac_set has no primary");
  }
  return util::Status::OK;
}

}  // anonymous namespace

// static
util::StatusOr<std::unique_ptr<Mac>> MacSetWrapper::NewMac(
    std::unique_ptr<PrimitiveSet<Mac>> mac_set) {
  util::Status status = Validate(mac_set.get());
  if (!status.ok()) return status;
  std::unique_ptr<Mac> mac(new MacSetWrapper(std::move(mac_set)));
  return std::move(mac);
}

util::StatusOr<std::string> MacSetWrapper::ComputeMac(
    absl::string_view data) const {
  auto compute_mac_result =
      mac_set_->get_primary()->get_primitive().ComputeMac(data);
  if (!compute_mac_result.ok()) return compute_mac_result.status();
  const std::string& key_id = mac_set_->get_primary()->get_identifier();
  return key_id + compute_mac_result.ValueOrDie();
}

util::Status MacSetWrapper::VerifyMac(
    absl::string_view mac_value,
    absl::string_view data) const {
  if (mac_value.length() > CryptoFormat::kNonRawPrefixSize) {
    const std::string& key_id = std::string(mac_value.substr(0,
        CryptoFormat::kNonRawPrefixSize));
    auto primitives_result = mac_set_->get_primitives(key_id);
    if (primitives_result.ok()) {
      absl::string_view raw_mac_value =
          mac_value.substr(CryptoFormat::kNonRawPrefixSize);
      for (auto& mac_entry : *(primitives_result.ValueOrDie())) {
        Mac& mac = mac_entry.get_primitive();
        util::Status status = mac.VerifyMac(raw_mac_value, data);
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
        Mac& mac = mac_entry.get_primitive();
        util::Status status = mac.VerifyMac(mac_value, data);
      if (status.ok()) {
        return status;
      }
    }
  }
  return util::Status(util::error::INVALID_ARGUMENT, "verification failed");
}

}  // namespace tink
}  // namespace crypto
