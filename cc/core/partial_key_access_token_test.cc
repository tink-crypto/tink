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

#include <utility>

#include "tink/partial_key_access_token.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/attributes.h"
#include "tink/partial_key_access.h"

namespace crypto {
namespace tink {
namespace {

TEST(PartialKeyAccessTokenTest, CopyConstructor) {
  PartialKeyAccessToken token = GetPartialKeyAccess();
  PartialKeyAccessToken copy ABSL_ATTRIBUTE_UNUSED(token);
}

TEST(PartialKeyAccessTokenTest, CopyAssignment) {
  PartialKeyAccessToken token = GetPartialKeyAccess();
  PartialKeyAccessToken copy ABSL_ATTRIBUTE_UNUSED = token;
}

TEST(PartialKeyAccessTokenTest, MoveConstructor) {
  PartialKeyAccessToken token = GetPartialKeyAccess();
  PartialKeyAccessToken move ABSL_ATTRIBUTE_UNUSED(std::move(token));
}

TEST(PartialKeyAccessTokenTest, MoveAssignment) {
  PartialKeyAccessToken token = GetPartialKeyAccess();
  PartialKeyAccessToken move ABSL_ATTRIBUTE_UNUSED = std::move(token);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
