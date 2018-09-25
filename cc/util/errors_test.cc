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

#include <stdarg.h>

#include "gtest/gtest.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
// placeholder_google3_status_header, please ignore

namespace crypto {
namespace tink {
namespace {

class ErrorsTest : public ::testing::Test {
 protected:
  void SetUp() override {}
  void TearDown() override {}
};

TEST_F(ErrorsTest, ToStatusFTest) {
  const char* const msg1 = "test message 1";
  const char* const msg2 = "test message %s 2 %d";
  crypto::tink::util::Status status;

  status = ToStatusF(crypto::tink::util::error::OK, msg1);
  EXPECT_TRUE(status.ok());
  // if status is OK, error message is ignored
  EXPECT_EQ("", status.error_message());
  EXPECT_EQ(crypto::tink::util::error::OK, status.error_code());

  const char* expected_msg2 = "test message asdf 2 42";
  status = ToStatusF(crypto::tink::util::error::UNKNOWN, msg2, "asdf", 42);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(expected_msg2, status.error_message());
  EXPECT_EQ(crypto::tink::util::error::UNKNOWN, status.error_code());
}

// placeholder_status_conversion_test, please ignore

}  // namespace
}  // namespace tink
}  // namespace crypto
