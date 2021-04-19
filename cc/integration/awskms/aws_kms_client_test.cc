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
#include <string>
#include <vector>
#include <regex>

#include "aws/core/Aws.h"
#include "aws/kms/KMSClient.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;

namespace crypto {
namespace tink {
namespace integration {
namespace awskms {
namespace {

using crypto::tink::integration::awskms::AwsKmsClient;

TEST(AwsKmsClientTest, testBasic) {
  std::string aws_key1 = "aws-kms://arn:aws:kms:us-east-1:acc:some/key1";
  std::string aws_key2 = "aws-kms://arn:aws:kms:us-west-2:acc:other/key2";
  std::string non_aws_key = "gcp-kms:://some/gcp/key";
  std::string creds_file = std::string(getenv("TEST_SRCDIR")) +
                           "/tink_base/testdata/aws_credentials_cc.txt";

  {  // A client not bound to any particular key.
    auto client_result = AwsKmsClient::New("", creds_file);
    EXPECT_TRUE(client_result.ok()) << client_result.status();
    auto client = std::move(client_result.ValueOrDie());
    EXPECT_TRUE(client->DoesSupport(aws_key1));
    EXPECT_TRUE(client->DoesSupport(aws_key2));
    EXPECT_FALSE(client->DoesSupport(non_aws_key));
  }

  {  // A client bound to a specific AWS KMS key.
    auto client_result = AwsKmsClient::New(aws_key1, creds_file);
    EXPECT_TRUE(client_result.ok()) << client_result.status();
    auto client = std::move(client_result.ValueOrDie());
    EXPECT_TRUE(client->DoesSupport(aws_key1));
    EXPECT_FALSE(client->DoesSupport(aws_key2));
    EXPECT_FALSE(client->DoesSupport(non_aws_key));
  }
}

TEST(AwsKmsClientTest, ClientCreationAndRegistry) {
  std::string aws_key1 = "aws-kms://arn:aws:kms:us-east-1:acc:some/key1";
  std::string creds_file = absl::StrCat(
      getenv("TEST_SRCDIR"), "/tink_base/testdata/aws_credentials_cc.txt");

  auto client_result = AwsKmsClient::RegisterNewClient(aws_key1, creds_file);
  EXPECT_THAT(client_result, IsOk());

  auto registry_result = KmsClients::Get(aws_key1);
  EXPECT_THAT(registry_result.status(), IsOk());
}

TEST(AwsKmsClientTest, ClientCreationInvalidRegistry) {
  std::string non_aws_key =
      "gcp-kms://projects/someProject/.../cryptoKeys/key1";
  std::string creds_file =
      std::string(getenv("TEST_SRCDIR")) + "/tink_base/testdata/credential.json";

  auto client_result = AwsKmsClient::RegisterNewClient(non_aws_key, creds_file);
  EXPECT_THAT(client_result, StatusIs(util::error::INVALID_ARGUMENT));
}

TEST(AwsKmsClientTest, ConfigCreation) {
  std::string aws_key = "aws-kms://arn:aws:kms:us-east-1:acc:some/key1";
  std::string creds_file = absl::StrCat(
      getenv("TEST_SRCDIR"), "/tink_base/testdata/aws_credentials_cc.txt");

  auto client_result = AwsKmsClient::New(aws_key, creds_file);
  EXPECT_THAT(client_result.status(), IsOk());

  auto config = client_result.ValueOrDie()->GetConfig();
  EXPECT_EQ("us-east-1", config.region);
  EXPECT_EQ(Aws::Http::Scheme::HTTPS, config.scheme);
  EXPECT_EQ(30000, config.connectTimeoutMs);
  EXPECT_EQ(60000, config.requestTimeoutMs);
}

TEST(AwsKmsClientTest, ConfigCreationWithHttpsProxyWithBasicAuth) {
  setenv("HTTPS_PROXY", "https://username:password@someproxy.host:1234", 1);

  std::string aws_key = "aws-kms://arn:aws:kms:us-east-1:acc:some/key1";
  std::string creds_file = absl::StrCat(
      getenv("TEST_SRCDIR"), "/tink_base/testdata/aws_credentials_cc.txt");

  auto client_result = AwsKmsClient::New(aws_key, creds_file);
  EXPECT_THAT(client_result.status(), IsOk());

  auto config = client_result.ValueOrDie()->GetConfig();

  EXPECT_EQ(Aws::Http::Scheme::HTTPS, config.proxyScheme);
  EXPECT_EQ("username", config.proxyUserName);
  EXPECT_EQ("password", config.proxyPassword);
  EXPECT_EQ("someproxy.host", config.proxyHost);
  EXPECT_EQ(1234, config.proxyPort);
}

TEST(AwsKmsClientTest, ConfigCreationWithHttpsProxyWithoutBasicAuth) {
  setenv("HTTPS_PROXY", "https://someproxy.host:1234", 1);

  std::string aws_key = "aws-kms://arn:aws:kms:us-east-1:acc:some/key1";
  std::string creds_file = absl::StrCat(
      getenv("TEST_SRCDIR"), "/tink_base/testdata/aws_credentials_cc.txt");

  auto client_result = AwsKmsClient::New(aws_key, creds_file);
  EXPECT_THAT(client_result.status(), IsOk());

  auto config = client_result.ValueOrDie()->GetConfig();

  EXPECT_EQ(Aws::Http::Scheme::HTTPS, config.proxyScheme);
  EXPECT_EQ(Aws::String(), config.proxyUserName);
  EXPECT_EQ(Aws::String(), config.proxyPassword);
  EXPECT_EQ("someproxy.host", config.proxyHost);
  EXPECT_EQ(1234, config.proxyPort);
}

TEST(AwsKmsClientTest, ConfigCreationWithHttpsProxyWithHttpScheme) {
  setenv("HTTPS_PROXY", "http://username:password@someproxy.host:1234", 1);

  std::string aws_key = "aws-kms://arn:aws:kms:us-east-1:acc:some/key1";
  std::string creds_file = absl::StrCat(
      getenv("TEST_SRCDIR"), "/tink_base/testdata/aws_credentials_cc.txt");

  auto client_result = AwsKmsClient::New(aws_key, creds_file);
  EXPECT_THAT(client_result.status(), IsOk());

  auto config = client_result.ValueOrDie()->GetConfig();

  EXPECT_EQ(Aws::Http::Scheme::HTTP, config.proxyScheme);
  EXPECT_EQ("username", config.proxyUserName);
  EXPECT_EQ("password", config.proxyPassword);
  EXPECT_EQ("someproxy.host", config.proxyHost);
  EXPECT_EQ(1234, config.proxyPort);
}



}  // namespace
}  // namespace awskms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
