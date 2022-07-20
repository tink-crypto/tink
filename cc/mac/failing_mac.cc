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
#include "tink/mac/failing_mac.h"

#include <string>
#include <utility>

#include "absl/strings/string_view.h"

namespace crypto {
namespace tink {
namespace {

// A MAC that always returns a kInternal status on API calls.
class AlwaysFailMac : public Mac {
 public:
  explicit AlwaysFailMac(std::string message) : message_(std::move(message)) {}

  util::StatusOr<std::string> ComputeMac(
      absl::string_view /*data*/) const override {
    return util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat("AlwaysFailMac will always fail on ComputeMac (msg=",
                     message_, ")"));
  }

  util::Status VerifyMac(absl::string_view /*mac_value*/,
                         absl::string_view /*data*/) const override {
    return util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat("AlwaysFailMac will always fail on VerifyMac (msg=",
                     message_, ")"));
  }

 private:
  const std::string message_;
};

}  // namespace

std::unique_ptr<Mac> CreateAlwaysFailingMac(std::string message) {
  return absl::make_unique<AlwaysFailMac>(std::move(message));
}

}  // namespace tink
}  // namespace crypto
