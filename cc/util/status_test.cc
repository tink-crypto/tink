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

#include "tink/util/status.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"

namespace crypto {
namespace tink {
namespace util {
namespace {

#ifndef TINK_USE_ABSL_STATUS
TEST(StatusTest, CreateNonOkStatusWithAbslStatusCode) {
  Status util_status = Status(error::Code::CANCELLED, "message");
  Status absl_status = Status(absl::StatusCode::kCancelled, "message");
  ASSERT_EQ(util_status, absl_status);
}

TEST(StatusTest, CreateOkStatusWithAbslStatusCode) {
  Status util_status = Status(error::Code::OK, "message");
  Status absl_status = Status(absl::StatusCode::kOk, "message");
  ASSERT_EQ(util_status, absl_status);
  ASSERT_EQ(absl_status.message(), "");
}

TEST(StatusTest, ConvertNonOkStatus) {
  Status util_status = Status(error::Code::RESOURCE_EXHAUSTED, "message");
  absl::Status absl_status = util_status;
  ASSERT_EQ(util_status.code(), absl_status.code());
  ASSERT_EQ(util_status.message(), absl_status.message());
}
#endif

TEST(StatusTest, ConvertOkStatus) {
  Status util_status = OkStatus();
  absl::Status absl_status = util_status;
  ASSERT_TRUE(absl_status.ok());
  ASSERT_EQ(absl_status.message(), "");
}

}  // namespace
}  // namespace util
}  // namespace tink
}  // namespace crypto
