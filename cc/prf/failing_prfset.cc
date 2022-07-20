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
#include "tink/prf/failing_prfset.h"

#include <map>
#include <memory>
#include <string>
#include <utility>

namespace crypto {
namespace tink {
namespace {

// A Prf that always returns a kInternal status on API calls.
class AlwaysFailPrf : public Prf {
 public:
  explicit AlwaysFailPrf(std::string message) : message_(std::move(message)) {}

  util::StatusOr<std::string> Compute(absl::string_view /*input*/,
                                      size_t /*output_length*/) const override {
    return util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat(
            "AlwaysFailPrf will always fail on Compute (msg=", message_, ")"));
  }

 private:
  const std::string message_;
};

// A PrfSet that always returns a kInternal status on API calls.
class AlwaysFailPrfSet : public PrfSet {
 public:
  explicit AlwaysFailPrfSet(std::string message)
      : message_(std::move(message)),
        always_fail_prf_0_(absl::make_unique<AlwaysFailPrf>(message_)),
        always_fail_prf_1_(absl::make_unique<AlwaysFailPrf>(message_)),
        always_fail_prf_2_(absl::make_unique<AlwaysFailPrf>(message_)),
        prfs_({{0, always_fail_prf_0_.get()},
               {1, always_fail_prf_1_.get()},
               {2, always_fail_prf_2_.get()}}) {}

  uint32_t GetPrimaryId() const override { return 0; }

  // A map of the PRFs represented by the keys in this keyset.
  // The map is guaranteed to contain getPrimaryId() as a key.
  const std::map<uint32_t, Prf*>& GetPrfs() const override { return prfs_; };

  util::StatusOr<std::string> ComputePrimary(absl::string_view /*input*/,
                                             size_t /*output_length*/) const {
    return util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat(
            "AlwaysFailPrfSet will always fail on ComputePrimary (msg=",
            message_, ")"));
  }

 private:
  const std::string message_;
  std::unique_ptr<AlwaysFailPrf> always_fail_prf_0_;
  std::unique_ptr<AlwaysFailPrf> always_fail_prf_1_;
  std::unique_ptr<AlwaysFailPrf> always_fail_prf_2_;
  std::map<uint32_t, Prf*> prfs_;
};
}  // namespace

std::unique_ptr<Prf> CreateAlwaysFailingPrf(std::string message) {
  return absl::make_unique<AlwaysFailPrf>(std::move(message));
}

std::unique_ptr<PrfSet> CreateAlwaysFailingPrfSet(std::string message) {
  return absl::make_unique<AlwaysFailPrfSet>(std::move(message));
}

}  // namespace tink
}  // namespace crypto
