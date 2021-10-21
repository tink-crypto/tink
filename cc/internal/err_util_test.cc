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
#include "tink/internal/err_util.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "openssl/bio.h"
#include "openssl/err.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::testing::AllOf;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::SizeIs;

TEST(GetSslErrorsTest, ReturnsExpectedErrorrs) {
  // Artificially add some errors to OpenSSL/BoringSSL's error queue.
  OPENSSL_PUT_ERROR(BIO, BIO_R_UNINITIALIZED);
  OPENSSL_PUT_ERROR(BIO, BIO_R_WRITE_TO_READ_ONLY_BIO);
  OPENSSL_PUT_ERROR(BIO, BIO_R_UNSUPPORTED_METHOD);

  std::string error = GetSslErrors();

  // OpenSSL/BoringSSL returns each error as a null terminated char*; since we
  // accumulate each of them into a std::string, the resulting string will be
  // "double null terminated". So we ignore the last char, and split by \n.
  auto errors_without_last_char = absl::string_view(error);
  errors_without_last_char.remove_suffix(1);
  std::vector<std::string> lines =
      absl::StrSplit(errors_without_last_char, '\n');
  ASSERT_THAT(lines, SizeIs(3));
  EXPECT_THAT(lines[0], AllOf(HasSubstr("BIO"), HasSubstr("UNINITIALIZED")));
  EXPECT_THAT(lines[1],
              AllOf(HasSubstr("BIO"), HasSubstr("WRITE_TO_READ_ONLY_BIO")));
  EXPECT_THAT(lines[2],
              AllOf(HasSubstr("BIO"), HasSubstr("UNSUPPORTED_METHOD")));
  // A second call to GetSslErrors() returns an empty string because the
  // OpenSSL/BoringSSL error queue is empty.
  EXPECT_THAT(GetSslErrors(), IsEmpty());
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
