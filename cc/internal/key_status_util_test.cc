// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/internal/key_status_util.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/key_status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeyStatusType;

TEST(KeyStatusUtilTest, FromKeyStatusType) {
  util::StatusOr<KeyStatus> enabled = FromKeyStatusType(KeyStatusType::ENABLED);
  EXPECT_THAT(enabled, IsOkAndHolds(KeyStatus::kEnabled));

  util::StatusOr<KeyStatus> disabled =
      FromKeyStatusType(KeyStatusType::DISABLED);
  EXPECT_THAT(disabled, IsOkAndHolds(KeyStatus::kDisabled));

  util::StatusOr<KeyStatus> destroyed =
      FromKeyStatusType(KeyStatusType::DESTROYED);
  EXPECT_THAT(destroyed, IsOkAndHolds(KeyStatus::kDestroyed));

  util::StatusOr<KeyStatus> unknown =
      FromKeyStatusType(KeyStatusType::UNKNOWN_STATUS);
  EXPECT_THAT(unknown.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(KeyStatusUtilTest, ToKeyStatusType) {
  util::StatusOr<KeyStatusType> enabled = ToKeyStatusType(KeyStatus::kEnabled);
  EXPECT_THAT(enabled, IsOkAndHolds(KeyStatusType::ENABLED));

  util::StatusOr<KeyStatusType> disabled =
      ToKeyStatusType(KeyStatus::kDisabled);
  EXPECT_THAT(disabled, IsOkAndHolds(KeyStatusType::DISABLED));

  util::StatusOr<KeyStatusType> destroyed =
      ToKeyStatusType(KeyStatus::kDestroyed);
  EXPECT_THAT(destroyed, IsOkAndHolds(KeyStatusType::DESTROYED));

  util::StatusOr<KeyStatusType> unknown = ToKeyStatusType(
      KeyStatus::kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements);
  EXPECT_THAT(unknown.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
