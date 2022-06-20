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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::StatusIs;
using ::testing::HasSubstr;

TEST(AlwaysFailPublicKeySign, SignFails) {
  std::unique_ptr<PublicKeySign> failing_sign =
      CreateAlwaysFailingPublicKeySign();

  EXPECT_THAT(failing_sign->Sign("message").status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(AlwaysFailPublicKeySign, SignFailsContainsMessage) {
  const std::string expected_message = "expected_message";
  std::unique_ptr<PublicKeySign> failing_sign =
      CreateAlwaysFailingPublicKeySign(expected_message);

  EXPECT_THAT(
      failing_sign->Sign("message").status(),
      StatusIs(absl::StatusCode::kInternal, HasSubstr(expected_message)));
}

TEST(AlwaysFailPublicKeyVerify, VerifyFails) {
  std::unique_ptr<PublicKeyVerify> failing_verify =
      CreateAlwaysFailingPublicKeyVerify();

  EXPECT_THAT(failing_verify->Verify("signature", "message"),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(AlwaysFailPublicKeyVerify, VerifyFailsContainsMessage) {
  const std::string expected_message = "expected_message";
  std::unique_ptr<PublicKeyVerify> failing_verify =
      CreateAlwaysFailingPublicKeyVerify(expected_message);

  EXPECT_THAT(
      failing_verify->Verify("signature", "message"),
      StatusIs(absl::StatusCode::kInternal, HasSubstr(expected_message)));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
