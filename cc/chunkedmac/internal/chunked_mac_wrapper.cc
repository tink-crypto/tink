// Copyright 2022 Google LLC
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

#include "tink/chunkedmac/internal/chunked_mac_wrapper.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/chunked_mac.h"
#include "tink/crypto_format.h"
#include "tink/internal/util.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::google::crypto::tink::OutputPrefixType;

class ChunkedMacComputationSetWrapper : public ChunkedMacComputation {
 public:
  explicit ChunkedMacComputationSetWrapper(
      std::unique_ptr<ChunkedMacComputation> computation,
      absl::string_view tag_prefix, OutputPrefixType output_prefix_type)
      : computation_(std::move(computation)),
        tag_prefix_(tag_prefix),
        output_prefix_type_(output_prefix_type) {}

  util::Status Update(absl::string_view data) override;

  util::StatusOr<std::string> ComputeMac() override;

 private:
  const std::unique_ptr<ChunkedMacComputation> computation_;
  const std::string tag_prefix_;
  const OutputPrefixType output_prefix_type_;
};

util::Status ChunkedMacComputationSetWrapper::Update(absl::string_view data) {
  return computation_->Update(data);
}

util::StatusOr<std::string> ChunkedMacComputationSetWrapper::ComputeMac() {
  if (output_prefix_type_ == OutputPrefixType::LEGACY) {
    util::Status append_status = computation_->Update(std::string("\x00", 1));
    if (!append_status.ok()) return append_status;
  }
  util::StatusOr<std::string> raw_tag = computation_->ComputeMac();
  if (!raw_tag.ok()) return raw_tag.status();
  return absl::StrCat(tag_prefix_, *raw_tag);
}

class ChunkedMacVerificationWithPrefixType : public ChunkedMacVerification {
 public:
  explicit ChunkedMacVerificationWithPrefixType(
      std::unique_ptr<ChunkedMacVerification> verification,
      OutputPrefixType output_prefix_type)
      : verification_(std::move(verification)),
        output_prefix_type_(output_prefix_type) {}

  util::Status Update(absl::string_view data) override;

  util::Status VerifyMac() override;

 private:
  const std::unique_ptr<ChunkedMacVerification> verification_;
  const OutputPrefixType output_prefix_type_;
};

util::Status ChunkedMacVerificationWithPrefixType::Update(
    absl::string_view data) {
  return verification_->Update(data);
}

util::Status ChunkedMacVerificationWithPrefixType::VerifyMac() {
  if (output_prefix_type_ == OutputPrefixType::LEGACY) {
    util::Status append_status = verification_->Update(std::string("\x00", 1));
    if (!append_status.ok()) return append_status;
  }
  return verification_->VerifyMac();
}

class ChunkedMacVerificationSetWrapper : public ChunkedMacVerification {
 public:
  explicit ChunkedMacVerificationSetWrapper(
      std::unique_ptr<
          std::vector<std::unique_ptr<ChunkedMacVerificationWithPrefixType>>>
          verifications)
      : verifications_(std::move(verifications)) {}

  util::Status Update(absl::string_view data) override;

  util::Status VerifyMac() override;

 private:
  const std::unique_ptr<
      std::vector<std::unique_ptr<ChunkedMacVerificationWithPrefixType>>>
      verifications_;
};

util::Status ChunkedMacVerificationSetWrapper::Update(absl::string_view data) {
  util::Status status =
      util::Status(absl::StatusCode::kUnknown, "Update failed.");
  for (auto& verification : *verifications_) {
    util::Status individual_update_status = verification->Update(data);
    if (individual_update_status.ok()) {
      // At least one update succeeded.
      status = util::OkStatus();
    }
  }
  return status;
}

util::Status ChunkedMacVerificationSetWrapper::VerifyMac() {
  for (auto& verification : *verifications_) {
    absl::Status status = verification->VerifyMac();
    if (status.ok()) {
      // One of the verifications succeeded.
      return status;
    }
  }
  return util::Status(absl::StatusCode::kUnknown, "Verification failed.");
}

class ChunkedMacSetWrapper : public ChunkedMac {
 public:
  explicit ChunkedMacSetWrapper(
      std::unique_ptr<PrimitiveSet<ChunkedMac>> mac_set)
      : mac_set_(std::move(mac_set)) {}

  util::StatusOr<std::unique_ptr<ChunkedMacComputation>> CreateComputation()
      const override;

  util::StatusOr<std::unique_ptr<ChunkedMacVerification>> CreateVerification(
      absl::string_view tag) const override;

  ~ChunkedMacSetWrapper() override {}

 private:
  std::unique_ptr<PrimitiveSet<ChunkedMac>> mac_set_;
};

util::Status Validate(PrimitiveSet<ChunkedMac>* mac_set) {
  if (mac_set == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "mac_set must be non-NULL");
  }
  if (mac_set->get_primary() == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "mac_set has no primary");
  }
  return util::OkStatus();
}

util::StatusOr<std::unique_ptr<ChunkedMacComputation>>
ChunkedMacSetWrapper::CreateComputation() const {
  const PrimitiveSet<ChunkedMac>::Entry<ChunkedMac>* primary =
      mac_set_->get_primary();
  util::StatusOr<std::unique_ptr<ChunkedMacComputation>> computation =
      primary->get_primitive().CreateComputation();
  if (!computation.ok()) return computation.status();
  return {absl::make_unique<ChunkedMacComputationSetWrapper>(
      *std::move(computation), primary->get_identifier(),
      primary->get_output_prefix_type())};
}

util::StatusOr<std::unique_ptr<ChunkedMacVerification>>
ChunkedMacSetWrapper::CreateVerification(absl::string_view tag) const {
  tag = internal::EnsureStringNonNull(tag);

  auto verifications = absl::make_unique<
      std::vector<std::unique_ptr<ChunkedMacVerificationWithPrefixType>>>();

  // Create verifications for all non-RAW keys with matching identifiers by
  // removing prefix.
  if (tag.length() > CryptoFormat::kNonRawPrefixSize) {
    absl::string_view key_id = tag.substr(0, CryptoFormat::kNonRawPrefixSize);
    auto primitives_result = mac_set_->get_primitives(key_id);
    if (primitives_result.ok()) {
      absl::string_view raw_tag = tag.substr(CryptoFormat::kNonRawPrefixSize);
      for (auto& mac_entry : *(primitives_result.value())) {
        util::StatusOr<std::unique_ptr<ChunkedMacVerification>> verification =
            mac_entry->get_primitive().CreateVerification(raw_tag);
        if (verification.ok()) {
          auto verification_with_prefix =
              absl::make_unique<ChunkedMacVerificationWithPrefixType>(
                  *std::move(verification),
                  mac_entry->get_output_prefix_type());
          verifications->push_back(std::move(verification_with_prefix));
        }
      }
    }
  }

  // Create verifications for all RAW keys by including prefix.
  auto raw_primitives_result = mac_set_->get_raw_primitives();
  if (raw_primitives_result.ok()) {
    for (auto& mac_entry : *(raw_primitives_result.value())) {
      util::StatusOr<std::unique_ptr<ChunkedMacVerification>> verification =
          mac_entry->get_primitive().CreateVerification(tag);
      if (verification.ok()) {
        auto verification_with_prefix =
            absl::make_unique<ChunkedMacVerificationWithPrefixType>(
                *std::move(verification), mac_entry->get_output_prefix_type());
        verifications->push_back(std::move(verification_with_prefix));
      }
    }
  }

  return {absl::make_unique<ChunkedMacVerificationSetWrapper>(
      std::move(verifications))};
}

}  // namespace

util::StatusOr<std::unique_ptr<ChunkedMac>> ChunkedMacWrapper::Wrap(
    std::unique_ptr<PrimitiveSet<ChunkedMac>> mac_set) const {
  util::Status status = Validate(mac_set.get());
  if (!status.ok()) return status;
  return {absl::make_unique<ChunkedMacSetWrapper>(std::move(mac_set))};
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
