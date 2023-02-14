// Copyright 2019 Google LLC
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

#include "tink/integration/awskms/aws_kms_client.h"

#include <cstdlib>
#include <fstream>
#include <ios>
#include <string>
#include <vector>

#include "aws/core/Aws.h"
#include "aws/kms/KMSClient.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace integration {
namespace awskms {
namespace {

using ::crypto::tink::integration::awskms::AwsKmsClient;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::testing::IsNull;
using ::testing::IsSubstring;
using ::testing::Not;

constexpr absl::string_view kAwsKey1 =
    "aws-kms://arn:aws:kms:us-east-1:acc:some/key1";
constexpr absl::string_view kAwsKey2 =
    "aws-kms://arn:aws:kms:us-east-1:acc:some/key2";
constexpr absl::string_view kNonAwsKey = "gcp-kms:://some/gcp/key";

std::string GetCredentialsFilePath() {
  return absl::StrCat(getenv("TEST_SRCDIR"), "/", getenv("TEST_WORKSPACE"), "/",
                      "testdata/aws/credentials.ini");
}

TEST(AwsKmsClientTest, CreateClientNotBoundToSpecificKeySupportsAllValidKeys) {
  std::string creds_file = GetCredentialsFilePath();
  util::StatusOr<std::unique_ptr<AwsKmsClient>> client =
      AwsKmsClient::New(/*key_uri=*/"", creds_file);
  ASSERT_THAT(client, IsOk());
  EXPECT_TRUE((*client)->DoesSupport(kAwsKey1));
  EXPECT_TRUE((*client)->DoesSupport(kAwsKey2));
  EXPECT_FALSE((*client)->DoesSupport(kNonAwsKey));
}

// Test that a client that is bound to a specific key does not support a
// different key URI.
TEST(AwsKmsClientTest, CreateClientBoundToSpecificKeySupportOnlyOneKey) {
  std::string creds_file = GetCredentialsFilePath();
  util::StatusOr<std::unique_ptr<AwsKmsClient>> client =
      AwsKmsClient::New(kAwsKey1, creds_file);
  ASSERT_THAT(client, IsOk());
  EXPECT_TRUE((*client)->DoesSupport(kAwsKey1));
  EXPECT_FALSE((*client)->DoesSupport(kAwsKey2));
  EXPECT_FALSE((*client)->DoesSupport(kNonAwsKey));
}

TEST(AwsKmsClientTest, RegisterKmsClient) {
  std::string creds_file = GetCredentialsFilePath();
  ASSERT_THAT(AwsKmsClient::RegisterNewClient(kAwsKey1, creds_file), IsOk());
  util::StatusOr<const KmsClient*> kms_client = KmsClients::Get(kAwsKey1);
  EXPECT_THAT(kms_client, IsOkAndHolds(Not(IsNull())));
}

TEST(AwsKmsClientTest, RegisterKmsClientFailsWhenKeyIsInvalid) {
  util::Status client = AwsKmsClient::RegisterNewClient(
      "gcp-kms://projects/someProject/.../cryptoKeys/key1",
      GetCredentialsFilePath());
  EXPECT_THAT(client, StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_PRED_FORMAT2(IsSubstring, "Invalid key URI",
                      std::string(client.message()));
}

TEST(AwsKmsClientTest, RegisterKmsClientFailsWhenCredentialsDoNotExist) {
  util::Status client =
      AwsKmsClient::RegisterNewClient(kAwsKey1, "this/file/does/not/exist.ini");
  EXPECT_THAT(client, StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_PRED_FORMAT2(IsSubstring, "Error opening file",
                      std::string(client.message()));
}

TEST(AwsKmsClientTest, RegisterKmsClientFailsWhenMalformedCredentials) {
  // Create an invalid credentials file.
  std::string malformed_content = "These are malformed credentials.";
  std::string invalid_credentials_file =
      absl::StrCat(getenv("TEST_TMPDIR"), "/", "invalid.ini");
  std::ofstream out_stream(invalid_credentials_file, std::ios::binary);
  out_stream.write(malformed_content.data(), malformed_content.size());
  out_stream.close();

  util::Status client =
      AwsKmsClient::RegisterNewClient(kAwsKey1, invalid_credentials_file);
  EXPECT_THAT(client, StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_PRED_FORMAT2(IsSubstring, "Invalid format",
                      std::string(client.message()));
}

}  // namespace
}  // namespace awskms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
