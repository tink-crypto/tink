// Copyright 2018 Google Inc.
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

#ifndef TINK_UTIL_TEST_MATCHERS_H_
#define TINK_UTIL_TEST_MATCHERS_H_

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace test {

// Matches a util::StatusOk() value.
// This is better than EXPECT_TRUE(status.ok())
// because the error message is a part of the failure messsage.
MATCHER(IsOk, "is a Status with an OK value") {
  if (arg.ok()) {
    return true;
  }
  *result_listener << arg.ToString();
  return false;
}

// Matches a Status with the specified 'code' as error_code().
MATCHER_P(StatusIs, code,
          "is a Status with a " + util::ErrorCodeString(code) + " code") {
  if (arg.CanonicalCode() == code) {
    return true;
  }
  *result_listener << ::testing::PrintToString(arg);
  return false;
}

// Matches a Status whose error_code() equals 'code', and whose
// error_message() matches 'message_macher'.
MATCHER_P2(StatusIs, code, message_matcher, "") {
  return (arg.CanonicalCode() == code) &&
         testing::Matches(message_matcher)(arg.error_message());
}

// Matches a Keyset::Key with `key`.
MATCHER_P(EqualsKey, key, "is equals to the expected key") {
  if (arg.key_id() == key.key_id() && arg.status() == key.status() &&
         arg.output_prefix_type() == key.output_prefix_type() &&
         arg.key_data().type_url() == key.key_data().type_url() &&
         arg.key_data().key_material_type() ==
             key.key_data().key_material_type() &&
         arg.key_data().value() == key.key_data().value()) {
    return true;
  }
  *result_listener << arg.DebugString();
  return false;
}

}  // namespace test
}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_TEST_MATCHERS_H_
