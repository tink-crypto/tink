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
#include "tink/hybrid/failing_hybrid.h"

#include <string>
#include <utility>

#include "tink/hybrid_encrypt.h"
#include "absl/strings/string_view.h"

namespace crypto {
namespace tink {
namespace {

// A HybridEncrypt which will always return a kInternal status on API calls.
class AlwaysFailHybridEncrypt : public HybridEncrypt {
 public:
  explicit AlwaysFailHybridEncrypt(std::string message)
      : message_(std::move(message)) {}

  util::StatusOr<std::string> Encrypt(
      absl::string_view plaintext,
      absl::string_view associated_data) const override {
    return util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat(
            "AlwaysFailHybridEncrypt will always fail on encrypt (msg=",
            message_, ")"));
  }

 private:
  const std::string message_;
};

// A HybridDecrypt which will always return a kInternal status on API calls.
class AlwaysFailHybridDecrypt : public HybridDecrypt {
 public:
  explicit AlwaysFailHybridDecrypt(std::string message)
      : message_(std::move(message)) {}

  util::StatusOr<std::string> Decrypt(
      absl::string_view plaintext,
      absl::string_view associated_data) const override {
    return util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat(
            "AlwaysFailHybridDecrypt will always fail on decrypt (msg=",
            message_, ")"));
  }

 private:
  const std::string message_;
};

}  // namespace

std::unique_ptr<HybridEncrypt> CreateAlwaysFailingHybridEncrypt(
    std::string message) {
  return absl::make_unique<AlwaysFailHybridEncrypt>(std::move(message));
}

std::unique_ptr<HybridDecrypt> CreateAlwaysFailingHybridDecrypt(
    std::string message) {
  return absl::make_unique<AlwaysFailHybridDecrypt>(std::move(message));
}


}  // namespace tink
}  // namespace crypto
