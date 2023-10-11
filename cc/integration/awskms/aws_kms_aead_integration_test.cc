// Copyright 2023 Google LLC
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

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "aws/core/Aws.h"
#include "aws/core/auth/AWSCredentialsProvider.h"
#include "aws/core/auth/AWSCredentialsProviderChain.h"
#include "aws/core/client/ClientConfiguration.h"
#include "aws/core/utils/crypto/Factories.h"
#include "aws/core/utils/memory/AWSMemory.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/ascii.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/integration/awskms/aws_kms_aead.h"
#include "tink/integration/awskms/aws_kms_client.h"
#include "tink/integration/awskms/internal/test_file_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace integration {
namespace awskms {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::testing::Not;

constexpr absl::string_view kAwsKmsKeyUri =
    "aws-kms://arn:aws:kms:us-east-2:235739564943:key/"
    "3ee50705-5a82-4f5b-9753-05c4f473922f";

constexpr absl::string_view kAwsKmsKeyArn =
    "arn:aws:kms:us-east-2:235739564943:key/"
    "3ee50705-5a82-4f5b-9753-05c4f473922f";

constexpr absl::string_view kAwsKmsKeyAliasUri =
    "aws-kms://arn:aws:kms:us-east-2:235739564943:alias/"
    "unit-and-integration-testing";


TEST(AwsKmsAeadTest, EncryptDecrypt) {
  std::string credentials =
      internal::RunfilesPath("testdata/aws/credentials.ini");
  util::StatusOr<std::unique_ptr<AwsKmsClient>> client =
      AwsKmsClient::New(/*key_uri=*/"", credentials);
  ASSERT_THAT(client, IsOk());

  util::StatusOr<std::unique_ptr<Aead>> aead =
      (*client)->GetAead(kAwsKmsKeyUri);
  ASSERT_THAT(aead, IsOk());

  constexpr absl::string_view kPlaintext = "plaintext";
  constexpr absl::string_view kAssociatedData = "aad";

  util::StatusOr<std::string> ciphertext =
      (*aead)->Encrypt(kPlaintext, kAssociatedData);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*aead)->Decrypt(*ciphertext, kAssociatedData),
              IsOkAndHolds(kPlaintext));
}

TEST(AwsKmsAeadTest, EncryptDecryptWithKeyAlias) {
  std::string credentials =
      internal::RunfilesPath("testdata/aws/credentials.ini");
  util::StatusOr<std::unique_ptr<AwsKmsClient>> client =
      AwsKmsClient::New(/*key_uri=*/"", credentials);
  ASSERT_THAT(client, IsOk());

  util::StatusOr<std::unique_ptr<Aead>> aead =
      (*client)->GetAead(kAwsKmsKeyAliasUri);
  ASSERT_THAT(aead, IsOk());

  constexpr absl::string_view kPlaintext = "plaintext";
  constexpr absl::string_view kAssociatedData = "associatedData";

  util::StatusOr<std::string> ciphertext =
      (*aead)->Encrypt(kPlaintext, kAssociatedData);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*aead)->Decrypt(*ciphertext, kAssociatedData),
              IsOkAndHolds(kPlaintext));

  EXPECT_THAT((*aead)->Decrypt(*ciphertext, "invalidAssociatedData"),
              Not(IsOk()));
}

util::StatusOr<std::string> ReadFile(const std::string& filename) {
  std::ifstream input_stream;
  input_stream.open(filename, std::ifstream::in);
  if (!input_stream.is_open()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("Error opening file ", filename));
  }
  std::stringstream input;
  input << input_stream.rdbuf();
  input_stream.close();
  return input.str();
}

util::StatusOr<std::string> GetValue(absl::string_view name,
                                     absl::string_view line) {
  std::vector<std::string> parts = absl::StrSplit(line, '=');
  if (parts.size() != 2 || absl::StripAsciiWhitespace(parts[0]) != name) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("Expected line to have the format: ", name,
                                     " = value. Found: ", line));
  }
  return std::string(absl::StripAsciiWhitespace(parts[1]));
}

TEST(AwsKmsAeadTest, AwsKmsAeadNewWorks) {
  Aws::SDKOptions options;
  Aws::InitAPI(options);

  // Read credentials and get secret access key.
  std::string credentials_path =
      internal::RunfilesPath("testdata/aws/credentials.ini");
  util::StatusOr<std::string> creds = ReadFile(credentials_path);
  ASSERT_THAT(creds, IsOk());
  std::vector<std::string> creds_lines = absl::StrSplit(*creds, '\n');
  util::StatusOr<std::string> key_id =
      GetValue("aws_access_key_id", creds_lines[1]);
  ASSERT_THAT(key_id, IsOk());
  util::StatusOr<std::string> secret_key =
      GetValue("aws_secret_access_key", creds_lines[2]);
  ASSERT_THAT(secret_key, IsOk());

  // Create an Aws::KMS::KMSClient.
  Aws::Auth::AWSCredentials credentials =
      Aws::Auth::AWSCredentials(key_id->c_str(), secret_key->c_str());
  Aws::Client::ClientConfiguration config;
  config.region = "us-east-2";
  config.scheme = Aws::Http::Scheme::HTTPS;
  config.connectTimeoutMs = 30000;
  config.requestTimeoutMs = 60000;
  auto aws_client = Aws::MakeShared<Aws::KMS::KMSClient>(
      "tink::integration::awskms", credentials, config);

  util::StatusOr<std::unique_ptr<Aead>> aead =
      AwsKmsAead::New(kAwsKmsKeyArn, aws_client);
  ASSERT_THAT(aead, IsOk());

  constexpr absl::string_view kPlaintext = "plaintext";
  constexpr absl::string_view kAssociatedData = "associatedData";

  util::StatusOr<std::string> ciphertext =
      (*aead)->Encrypt(kPlaintext, kAssociatedData);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*aead)->Decrypt(*ciphertext, kAssociatedData),
              IsOkAndHolds(kPlaintext));

  EXPECT_THAT((*aead)->Decrypt(*ciphertext, "invalidAssociatedData"),
              Not(IsOk()));
}

}  // namespace
}  // namespace awskms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
