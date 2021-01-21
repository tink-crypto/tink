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

#include "tink/util/statusor.h"

#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace util {
namespace {

using ::testing::Eq;
using ::testing::Pointee;

TEST(StatusOrTest, ConvertOkToAbsl) {
  StatusOr<int> instance = 1;

  absl::StatusOr<int> converted = instance;
  ASSERT_TRUE(converted.ok());
  EXPECT_EQ(*converted, 1);
}

TEST(StatusOrTest, ConvertErrorToAbsl) {
  StatusOr<int> instance{
      Status(error::Code::INVALID_ARGUMENT, "Error message")};

  absl::StatusOr<int> converted = instance;
  ASSERT_FALSE(converted.ok());
  EXPECT_EQ(converted.status().code(), absl::StatusCode::kInvalidArgument);
  EXPECT_EQ(converted.status().message(), "Error message");
}

TEST(StatusOrTest, ConvertUncopyableToAbsl) {
  StatusOr<std::unique_ptr<int>> instance = absl::make_unique<int>(1);

  absl::StatusOr<std::unique_ptr<int>> converted = std::move(instance);
  ASSERT_TRUE(converted.ok());
  EXPECT_THAT(*converted, Pointee(Eq(1)));
}

}  // namespace
}  // namespace util
}  // namespace tink
}  // namespace crypto
