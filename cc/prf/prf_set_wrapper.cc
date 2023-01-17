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
#include "tink/prf/prf_set_wrapper.h"

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "tink/internal/monitoring_util.h"
#include "tink/internal/registry_impl.h"
#include "tink/monitoring/monitoring.h"
#include "tink/prf/prf_set.h"
#include "tink/util/status.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using google::crypto::tink::OutputPrefixType;

namespace {

constexpr absl::string_view kPrimitive = "prf";
constexpr absl::string_view kComputeApi = "compute";

class MonitoredPrf : public Prf {
 public:
  explicit MonitoredPrf(uint32_t key_id, const Prf* prf,
                        MonitoringClient* monitoring_client)
      : key_id_(key_id), prf_(prf), monitoring_client_(monitoring_client) {}
  ~MonitoredPrf() override = default;

  MonitoredPrf(MonitoredPrf&& other) = default;
  MonitoredPrf& operator=(MonitoredPrf&& other) = default;

  MonitoredPrf(const MonitoredPrf&) = delete;
  MonitoredPrf& operator=(const MonitoredPrf&) = delete;

  util::StatusOr<std::string> Compute(absl::string_view input,
                                      size_t output_length) const override {
    util::StatusOr<std::string> result = prf_->Compute(input, output_length);
    if (!result.ok()) {
      if (monitoring_client_ != nullptr) {
        monitoring_client_->LogFailure();
      }
      return result.status();
    }

    if (monitoring_client_ != nullptr) {
      monitoring_client_->Log(key_id_, input.size());
    }
    return result.value();
  }

 private:
  uint32_t key_id_;
  const Prf* prf_;
  MonitoringClient* monitoring_client_;
};

class PrfSetPrimitiveWrapper : public PrfSet {
 public:
  explicit PrfSetPrimitiveWrapper(
      std::unique_ptr<PrimitiveSet<Prf>> prf_set,
      std::unique_ptr<MonitoringClient> monitoring_client = nullptr)
      : prf_set_(std::move(prf_set)),
        monitoring_client_(std::move(monitoring_client)) {
    wrapped_prfs_.reserve(prf_set_->get_raw_primitives().value()->size());
    for (const auto& prf : *prf_set_->get_raw_primitives().value()) {
      std::unique_ptr<Prf> wrapped_prf = std::make_unique<MonitoredPrf>(
                                  prf->get_key_id(), &prf->get_primitive(),
                                  monitoring_client_.get());

      prfs_.insert({prf->get_key_id(), wrapped_prf.get()});
      wrapped_prfs_.push_back(std::move(wrapped_prf));
    }
  }

  uint32_t GetPrimaryId() const override {
    return prf_set_->get_primary()->get_key_id();
  }
  const std::map<uint32_t, Prf*>& GetPrfs() const override { return prfs_; }

  ~PrfSetPrimitiveWrapper() override = default;

 private:
  std::unique_ptr<PrimitiveSet<Prf>> prf_set_;
  std::unique_ptr<MonitoringClient> monitoring_client_;
  std::vector<std::unique_ptr<Prf>> wrapped_prfs_;
  std::map<uint32_t, Prf*> prfs_;
};

util::Status Validate(PrimitiveSet<Prf>* prf_set) {
  if (prf_set == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "prf_set must be non-NULL");
  }
  if (prf_set->get_primary() == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "prf_set has no primary");
  }
  for (auto prf : prf_set->get_all()) {
    if (prf->get_output_prefix_type() != OutputPrefixType::RAW) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "PrfSet should only be used with prefix type RAW");
    }
  }
  return util::OkStatus();
}

}  // namespace

util::StatusOr<std::unique_ptr<PrfSet>> PrfSetWrapper::Wrap(
    std::unique_ptr<PrimitiveSet<Prf>> prf_set) const {
  util::Status status = Validate(prf_set.get());
  if (!status.ok()) return status;

  MonitoringClientFactory* const monitoring_factory =
      internal::RegistryImpl::GlobalInstance().GetMonitoringClientFactory();
  // Monitoring is not enabled. Create a wrapper without monitoring clients.
  if (monitoring_factory == nullptr) {
    return {absl::make_unique<PrfSetPrimitiveWrapper>(std::move(prf_set))};
  }
  util::StatusOr<MonitoringKeySetInfo> keyset_info =
      internal::MonitoringKeySetInfoFromPrimitiveSet(*prf_set);
  if (!keyset_info.ok()) {
    return keyset_info.status();
  }
  util::StatusOr<std::unique_ptr<MonitoringClient>> monitoring_client =
      monitoring_factory->New(
          MonitoringContext(kPrimitive, kComputeApi, *keyset_info));
  if (!monitoring_client.ok()) {
    return monitoring_client.status();
  }
  return {absl::make_unique<PrfSetPrimitiveWrapper>(
      std::move(prf_set), *std::move(monitoring_client))};
}

}  // namespace tink
}  // namespace crypto
