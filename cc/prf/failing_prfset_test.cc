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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::StatusIs;
using ::testing::HasSubstr;

TEST(AlwaysFailPrf, ComputePrimaryFails) {
  std::unique_ptr<Prf> failing_prf = CreateAlwaysFailingPrf();

  EXPECT_THAT(failing_prf->Compute("someinput", 16).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(AlwaysFailPrf, ComputePrimaryFailsContainsMessage) {
  const std::string expected_message = "expected_message";
  std::unique_ptr<Prf> failing_prf = CreateAlwaysFailingPrf(expected_message);

  EXPECT_THAT(
      failing_prf->Compute("someinput", 16).status(),
      StatusIs(absl::StatusCode::kInternal, HasSubstr(expected_message)));
}

TEST(AlwaysFailPrfSet, ComputePrimaryFails) {
  std::unique_ptr<PrfSet> failing_prf_set = CreateAlwaysFailingPrfSet();

  EXPECT_THAT(failing_prf_set->ComputePrimary("someinput", 16).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(AlwaysFailPrfSet, ComputePrimaryFailsContainsMessage) {
  const std::string expected_message = "expected_message";
  std::unique_ptr<PrfSet> failing_prf_set =
      CreateAlwaysFailingPrfSet(expected_message);

  EXPECT_THAT(
      failing_prf_set->ComputePrimary("someinput", 16).status(),
      StatusIs(absl::StatusCode::kInternal, HasSubstr(expected_message)));
}

TEST(AlwaysFailPrfSet, GetPrfsReturnsFailingPrfs) {
  const std::string expected_message = "expected_message";
  std::unique_ptr<PrfSet> failing_prf_set =
      CreateAlwaysFailingPrfSet(expected_message);
  const std::map<uint32_t, Prf*>& prfs_map = failing_prf_set->GetPrfs();

  for (auto const& entry : prfs_map) {
    EXPECT_THAT(
        entry.second->Compute("someinput", 16).status(),
        StatusIs(absl::StatusCode::kInternal, HasSubstr(expected_message)));
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
