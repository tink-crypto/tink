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
#include "tink/signature/failing_signature.h"

#include <memory>
#include <string>
#include <utility>

#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"

namespace crypto {
namespace tink {
namespace {

// A PublicKeySign that always return a kInternal status on API calls.
class AlwaysFailPublicKeySign : public PublicKeySign {
 public:
  explicit AlwaysFailPublicKeySign(std::string message)
      : message_(std::move(message)) {}

  util::StatusOr<std::string> Sign(
      absl::string_view /*message*/) const override {
    return util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat("AlwaysFailPublicKeySign will always fail on sign (msg=",
                     message_, ")"));
  }

 private:
  const std::string message_;
};

// A PublicKeyVerify that always return a kInternal status on API calls.
class AlwaysFailPublicKeyVerify : public PublicKeyVerify {
 public:
  explicit AlwaysFailPublicKeyVerify(std::string message)
      : message_(std::move(message)) {}

  util::Status Verify(absl::string_view /*signature*/,
                      absl::string_view /*message*/) const override {
    return absl::InternalError(
        absl::StrCat(
            "AlwaysFailPublicKeyVerify will always fail on verify (msg=",
            message_, ")"));
  }

 private:
  const std::string message_;
};

}  // namespace

std::unique_ptr<PublicKeySign> CreateAlwaysFailingPublicKeySign(
    std::string message) {
  return absl::make_unique<AlwaysFailPublicKeySign>(std::move(message));
}

std::unique_ptr<PublicKeyVerify> CreateAlwaysFailingPublicKeyVerify(
    std::string message) {
  return absl::make_unique<AlwaysFailPublicKeyVerify>(std::move(message));
}

}  // namespace tink
}  // namespace crypto
