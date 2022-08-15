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
#include "tink/daead/failing_daead.h"

#include <memory>
#include <string>
#include <utility>

namespace crypto {
namespace tink {
namespace {

// A deterministic AEAD that always return a kInternal status on API calls.
class AlwaysFailDeterministicAead : public DeterministicAead {
 public:
  explicit AlwaysFailDeterministicAead(std::string message)
      : message_(std::move(message)) {}

  util::StatusOr<std::string> EncryptDeterministically(
      absl::string_view plaintext,
      absl::string_view associated_data) const override {
    return util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat(
            "AlwaysFailDeterministicAead will always fail on encrypt (msg=",
            message_, ")"));
  }

  util::StatusOr<std::string> DecryptDeterministically(
      absl::string_view ciphertext,
      absl::string_view associated_data) const override {
    return util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat(
            "AlwaysFailDeterministicAead will always fail on decrypt (msg=",
            message_, ")"));
  }

 private:
  const std::string message_;
};

}  // namespace

std::unique_ptr<DeterministicAead> CreateAlwaysFailingDeterministicAead(
    std::string message) {
  return absl::make_unique<AlwaysFailDeterministicAead>(std::move(message));
}

}  // namespace tink
}  // namespace crypto
