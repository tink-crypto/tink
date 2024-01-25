// Copyright 2024 Google LLC
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
#include "tink/internal/call_with_core_dump_protection.h"

#include "gtest/gtest.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

TEST(CallWithCoreDumpProtectionTest, Basic) {
  EXPECT_EQ(CallWithCoreDumpProtection([]() {
    return 1 + 2;
  }), 3);
}

TEST(CallWithCoreDumpProtectionTest, WithCapture) {
  int a = 10;
  int b = 20;
  EXPECT_EQ(CallWithCoreDumpProtection([&]() {
    return a + b;
  }), a + b);
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
