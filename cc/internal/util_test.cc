// Copyright 2021 Google LLC
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
#include "tink/internal/util.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/string_view.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

TEST(UtilTest, EnsureStringNonNull) {
  // Purposely create a string_view from nullptr.
  auto null_str = absl::string_view(nullptr, 0);
  EXPECT_EQ(EnsureStringNonNull(null_str), absl::string_view(""));
  auto uninit_str = absl::string_view();
  EXPECT_EQ(EnsureStringNonNull(uninit_str), absl::string_view(""));
  auto regular_str = absl::string_view("This is a non-empty non-null str");
  EXPECT_EQ(EnsureStringNonNull(regular_str), regular_str);
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
