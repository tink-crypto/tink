// Copyright 2019 Google LLC
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
#include "tink/integration/awskms/aws_kms_client.h"

#include <fstream>
#include <iostream>
#include <sstream>

#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "absl/strings/ascii.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "aws/core/Aws.h"
#include "aws/core/auth/AWSCredentialsProvider.h"
#include "aws/core/auth/AWSCredentialsProviderChain.h"
#include "aws/core/client/ClientConfiguration.h"
#include "aws/core/utils/crypto/Factories.h"
#include "aws/core/utils/memory/AWSMemory.h"
#include "aws/kms/KMSClient.h"
#include "tink/integration/awskms/aws_crypto.h"
#include "tink/integration/awskms/aws_kms_aead.h"
#include "tink/kms_client.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace integration {
namespace awskms {
namespace {

constexpr absl::string_view kKeyUriPrefix = "aws-kms://";

// Returns AWS key ARN contained in `key_uri`. If `key_uri` does not refer to an
// AWS key, returns an empty string.
util::StatusOr<std::string> GetKeyArn(absl::string_view key_uri) {
  if (!absl::StartsWithIgnoreCase(key_uri, kKeyUriPrefix)) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("Invalid key URI ", key_uri));
  }
  return std::string(key_uri.substr(kKeyUriPrefix.length()));
}

// Returns ClientConfiguration with region set to the value extracted from
// `key_arn`.
// An AWS key ARN is of the form
// arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab.
util::StatusOr<Aws::Client::ClientConfiguration>
    GetAwsClientConfig(absl::string_view key_arn) {
  std::vector<std::string> key_arn_parts = absl::StrSplit(key_arn, ':');
  if (key_arn_parts.size() < 6) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("Invalid key ARN ", key_arn));
  }
  Aws::Client::ClientConfiguration config;
  // 4th part of key arn.
  config.region = key_arn_parts[3].c_str();
  config.scheme = Aws::Http::Scheme::HTTPS;
  config.connectTimeoutMs = 30000;
  config.requestTimeoutMs = 60000;
  return config;
}

// Reads the specified file and returns the content as a string.
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

// Extracts a value of `name` from `line`, where `line` must be of the form:
// name = value
util::StatusOr<std::string> GetValue(absl::string_view name,
                                     absl::string_view line) {
  std::vector<std::string> parts = absl::StrSplit(line, '=');
  if (parts.size() != 2 || absl::StripAsciiWhitespace(parts[0]) != name) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Expected line in format ", name, " = value"));
  }
  return std::string(absl::StripAsciiWhitespace(parts[1]));
}

// Returns AWS credentials from the given `credential_path`.
//
// Credentials are retrieved as follows:
//
// If `credentials_path` is not empty the credentials in the given file are
// returned. The file should have the following format:
//
//   [default]
//   aws_access_key_id = your_access_key_id
//   aws_secret_access_key = your_secret_access_key
//
// If `credentials_path` is empty, the credentials are searched for in the
// following order:
//   1. In the file specified via environment variable
//   AWS_SHARED_CREDENTIALS_FILE
//   2. In the file specified via environment variable AWS_PROFILE
//   3. In the file ~/.aws/credentials
//   4. In the file ~/.aws/config
//   5. In values specified in environment variables AWS_ACCESS_KEY_ID,
//      AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN
//
// For more info on AWS credentials see:
// https://docs.aws.amazon.com/sdk-for-cpp/v1/developer-guide/credentials.html
// and documentation of Aws::Auth::EnvironmentAWSCredentialsProvider and
// Aws::Auth::ProfileConfigFileAWSCredentialsProvider.
util::StatusOr<Aws::Auth::AWSCredentials> GetAwsCredentials(
    absl::string_view credentials_path) {
  if (!credentials_path.empty()) {  // Read credentials from given file.
    auto creds_result = ReadFile(std::string(credentials_path));
    if (!creds_result.ok()) {
      return creds_result.status();
    }
    std::vector<std::string> creds_lines =
        absl::StrSplit(creds_result.value(), '\n');
    if (creds_lines.size() < 3) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Invalid format of credentials in file ",
                                       credentials_path));
    }
    auto key_id_result = GetValue("aws_access_key_id", creds_lines[1]);
    if (!key_id_result.ok()) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Invalid format of credentials in file ",
                                       credentials_path, " : ",
                                       key_id_result.status().message()));
    }
    auto secret_key_result = GetValue("aws_secret_access_key", creds_lines[2]);
    if (!secret_key_result.ok()) {
      return util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Invalid format of credentials in file ",
                       credentials_path, " : ",
                       secret_key_result.status().message()));
    }
    return Aws::Auth::AWSCredentials(key_id_result.value().c_str(),
                                     secret_key_result.value().c_str());
  }

  // Get default credentials.
  Aws::Auth::DefaultAWSCredentialsProviderChain provider_chain;
  return provider_chain.GetAWSCredentials();
}

}  // namespace

bool AwsKmsClient::aws_api_is_initialized_;
absl::Mutex AwsKmsClient::aws_api_init_mutex_;

void AwsKmsClient::InitAwsApi() {
  absl::MutexLock lock(&aws_api_init_mutex_);
  if (aws_api_is_initialized_) {
    return;
  }
  Aws::SDKOptions options;
  options.cryptoOptions.sha256Factory_create_fn = []() {
    return Aws::MakeShared<AwsSha256Factory>(kAwsCryptoAllocationTag);
  };
  options.cryptoOptions.sha256HMACFactory_create_fn = []() {
    return Aws::MakeShared<AwsSha256HmacFactory>(kAwsCryptoAllocationTag);
  };
  Aws::InitAPI(options);
  aws_api_is_initialized_ = true;
}

util::StatusOr<std::unique_ptr<AwsKmsClient>> AwsKmsClient::New(
    absl::string_view key_uri, absl::string_view credentials_path) {
  if (!aws_api_is_initialized_) {
    InitAwsApi();
  }
  // Read credentials.
  util::StatusOr<Aws::Auth::AWSCredentials> credentials =
      GetAwsCredentials(credentials_path);
  if (!credentials.ok()) {
    return credentials.status();
  }

  if (key_uri.empty()) {
    return absl::WrapUnique(new AwsKmsClient(*credentials));
  }

  // If a specific key is given, create an AWS KMSClient.
  util::StatusOr<std::string> key_arn = GetKeyArn(key_uri);
  if (!key_arn.ok()) {
    return key_arn.status();
  }
  util::StatusOr<Aws::Client::ClientConfiguration> client_config =
      GetAwsClientConfig(*key_arn);
  if (!client_config.ok()) {
    return client_config.status();
  }
  auto client = absl::WrapUnique(new AwsKmsClient(*key_arn, *credentials));
  // Create AWS KMSClient.
  client->aws_client_ = Aws::MakeShared<Aws::KMS::KMSClient>(
      kAwsCryptoAllocationTag, client->credentials_, *client_config);
  return std::move(client);
}

bool AwsKmsClient::DoesSupport(absl::string_view key_uri) const {
  util::StatusOr<std::string> key_arn = GetKeyArn(key_uri);
  if (!key_arn.ok()) {
    return false;
  }
  // If this is bound to a specific key, make sure the key ARNs are equal.
  return key_arn_.empty() ? true : key_arn_ == *key_arn;
}

util::StatusOr<std::unique_ptr<Aead>>
AwsKmsClient::GetAead(absl::string_view key_uri) const {
  if (!DoesSupport(key_uri)) {
    if (!key_arn_.empty()) {
      return util::Status(absl::StatusCode::kInvalidArgument,
          absl::StrCat("This client is bound to ", key_arn_,
                       " and cannot use key ", key_uri));
    }
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("This client does not support key ", key_uri));
  }

  // This client is bound to a specific key.
  if (!key_arn_.empty()) {
    return AwsKmsAead::New(key_arn_, aws_client_);
  }

  // Create an Aws::KMS::KMSClient for the given key.
  util::StatusOr<std::string> key_arn = GetKeyArn(key_uri);
  util::StatusOr<Aws::Client::ClientConfiguration> client_config =
      GetAwsClientConfig(*key_arn);
  if (!client_config.ok()) {
    return client_config.status();
  }
  auto aws_client = Aws::MakeShared<Aws::KMS::KMSClient>(
      kAwsCryptoAllocationTag, credentials_, *client_config);
  return AwsKmsAead::New(*key_arn, aws_client);
}

util::Status AwsKmsClient::RegisterNewClient(
    absl::string_view key_uri, absl::string_view credentials_path) {
  util::StatusOr<std::unique_ptr<AwsKmsClient>> client_result =
      AwsKmsClient::New(key_uri, credentials_path);
  if (!client_result.ok()) {
    return client_result.status();
  }

  return KmsClients::Add(*std::move(client_result));
}

}  // namespace awskms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
