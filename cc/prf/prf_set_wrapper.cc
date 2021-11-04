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

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/util/status.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using google::crypto::tink::OutputPrefixType;

namespace {

class PrfSetPrimitiveWrapper : public PrfSet {
 public:
  explicit PrfSetPrimitiveWrapper(std::unique_ptr<PrimitiveSet<Prf>> prf_set)
      : prf_set_(std::move(prf_set)) {
    for (const auto& prf : *prf_set_->get_raw_primitives().ValueOrDie()) {
      prfs_.insert({prf->get_key_id(), &prf->get_primitive()});
    }
  }

  uint32_t GetPrimaryId() const override {
    return prf_set_->get_primary()->get_key_id();
  }
  const std::map<uint32_t, Prf*>& GetPrfs() const override { return prfs_; }

  ~PrfSetPrimitiveWrapper() override {}

 private:
  std::unique_ptr<PrimitiveSet<Prf>> prf_set_;
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
  return {absl::make_unique<PrfSetPrimitiveWrapper>(std::move(prf_set))};
}

}  // namespace tink
}  // namespace crypto
