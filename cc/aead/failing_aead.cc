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
#include "tink/aead/failing_aead.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"

namespace crypto {
namespace tink {
namespace {

// An AEAD that always returns a kInternal status on API calls.
class AlwaysFailAead : public Aead {
 public:
  explicit AlwaysFailAead(std::string message)
      : message_(std::move(message)) {}

  util::StatusOr<std::string> Encrypt(
      absl::string_view plaintext,
      absl::string_view associated_data) const override {
    return util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat(
            "AlwaysFailAead will always fail on encrypt (msg=", message_, ")"));
  }

  util::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext,
      absl::string_view associated_data) const override {
    return util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat(
            "AlwaysFailAead will always fail on decrypt (msg=", message_, ")"));
  }

 private:
  const std::string message_;
};

}  // namespace

std::unique_ptr<Aead> CreateAlwaysFailingAead(absl::string_view message) {
  return absl::make_unique<AlwaysFailAead>(std::string(message));
}

}  // namespace tink
}  // namespace crypto
