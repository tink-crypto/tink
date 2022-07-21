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

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::StatusIs;
using ::testing::HasSubstr;

TEST(AlwaysFailMac, ComputeMacFails) {
  std::unique_ptr<Mac> failing_Mac = CreateAlwaysFailingMac();

  EXPECT_THAT(failing_Mac->ComputeMac("message").status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(AlwaysFailMac, ComputeMacFailsContainsMessage) {
  const std::string expected_message = "expected_message";
  std::unique_ptr<Mac> failing_Mac =
      CreateAlwaysFailingMac(expected_message);

  EXPECT_THAT(
      failing_Mac->ComputeMac("message").status(),
      StatusIs(absl::StatusCode::kInternal, HasSubstr(expected_message)));
}

TEST(AlwaysFailMac, VerifyMacFails) {
  std::unique_ptr<Mac> failing_Mac = CreateAlwaysFailingMac();

  EXPECT_THAT(failing_Mac->VerifyMac("tag", "message"),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(AlwaysFailMac, VerifyMacFailsContainsMessage) {
  const std::string expected_message = "expected_message";
  std::unique_ptr<Mac> failing_Mac =
      CreateAlwaysFailingMac(expected_message);

  EXPECT_THAT(
      failing_Mac->VerifyMac("tag", "message"),
      StatusIs(absl::StatusCode::kInternal, HasSubstr(expected_message)));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
