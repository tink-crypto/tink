// Copyright 2017 Google Inc.
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

#include "tink/util/errors.h"

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace {

TEST(ErrorsTest, ToStatusFAbslStatusCodeTest) {
  const char* const msg = "test message %s 2 %d";
  const char* expected_msg = "test message asdf 2 42";
  util::Status status = ToStatusF(absl::StatusCode::kUnknown, msg, "asdf", 42);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(expected_msg, status.message());
  EXPECT_EQ(absl::StatusCode::kUnknown, status.code());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
