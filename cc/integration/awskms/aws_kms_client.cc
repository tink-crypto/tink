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

#include <iostream>
#include <fstream>
#include <sstream>

#include "absl/strings/match.h"
#include "absl/strings/ascii.h"
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
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace integration {
namespace awskms {

namespace {

using crypto::tink::ToStatusF;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;

static constexpr char kKeyUriPrefix[] = "aws-kms://";

// Returns AWS key ARN contained in 'key_uri'.
// If 'key_uri' does not refer to an AWS key, returns an empty string.
std::string GetKeyArn(absl::string_view key_uri) {
  if (!absl::StartsWithIgnoreCase(key_uri, kKeyUriPrefix)) return "";
  return std::string(key_uri.substr(std::string(kKeyUriPrefix).length()));
}

// Returns ClientConfiguration with region set to the value
// extracted from 'key_arn'.
StatusOr<Aws::Client::ClientConfiguration>
    GetAwsClientConfig(absl::string_view key_arn) {
  std::vector<std::string> key_arn_parts = absl::StrSplit(key_arn, ':');
  if (key_arn_parts.size() < 6) {
    return ToStatusF(util::error::INVALID_ARGUMENT, "Invalid key ARN '%s'.",
                     key_arn);
  }
  Aws::Client::ClientConfiguration config;
  config.region = key_arn_parts[3].c_str();  // 4th part of key arn
  config.scheme = Aws::Http::Scheme::HTTPS;
  config.connectTimeoutMs = 30000;
  config.requestTimeoutMs = 60000;
  return config;
}

// Reads the specified file and returns the content as a string.
StatusOr<std::string> Read(const std::string& filename) {
  std::ifstream input_stream;
  input_stream.open(filename, std::ifstream::in);
  if (!input_stream.is_open()) {
    return ToStatusF(util::error::INVALID_ARGUMENT, "Error opening file '%s'.",
                     filename);
  }
  std::stringstream input;
  input << input_stream.rdbuf();
  input_stream.close();
  return input.str();
}

// Extracts a value of 'name' from 'line', where 'line' must be in format:
// name = some_value
StatusOr<std::string> GetValue(absl::string_view name, absl::string_view line) {
  std::vector<std::string> parts = absl::StrSplit(line, '=');
  if (parts.size() != 2 || absl::StripAsciiWhitespace(parts[0]) != name) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Expected line in format '%s = some_value'.", name);
  }
  return std::string(absl::StripAsciiWhitespace(parts[1]));
}

// Returns AWS credentials that are retrieved as follows:
//
// If 'credentials_path' is not empty, then only the specified file
// is accessed, which should contain lines in the following format:
//
//   [default]
//   aws_access_key_id = your_access_key_id
//   aws_secret_access_key = your_secret_access_key
//
// Otherwise, if 'credentials_path' is empty, the credentials are
// searched for in the following order:
//   1. file specified via environment variable AWS_SHARED_CREDENTIALS_FILE
//   2. file specified via environment variable AWS_PROFILE
//   3. file ~/.aws/credentials
//   4. file ~/.aws/config
//   5. values specified in environment variables AWS_ACCESS_KEY_ID,
//      AWS_SECRET_ACCESS_KEY and AWS_SESSION_TOKEN
//
// For more info on AWS credentials see:
// https://docs.aws.amazon.com/sdk-for-cpp/v1/developer-guide/credentials.html
// and documentation of Aws::Auth::EnvironmentAWSCredentialsProvider and
// Aws::Auth::ProfileConfigFileAWSCredentialsProvider.
//
StatusOr<Aws::Auth::AWSCredentials> GetAwsCredentials(
    absl::string_view credentials_path) {
  if (!credentials_path.empty()) {  // Read credentials from given file.
    auto creds_result = Read(std::string(credentials_path));
    if (!creds_result.ok()) return creds_result.status();
    std::vector<std::string> creds_lines =
        absl::StrSplit(creds_result.ValueOrDie(), '\n');
    if (creds_lines.size() < 3) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Invalid format of credentials in file '%s'.",
                       credentials_path);
    }
    auto key_id_result = GetValue("aws_access_key_id", creds_lines[1]);
    if (!key_id_result.ok()) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Invalid format of credentials in file '%s': %s",
                       credentials_path,
                       key_id_result.status().error_message());
    }
    auto secret_key_result = GetValue("aws_secret_access_key", creds_lines[2]);
    if (!secret_key_result.ok()) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Invalid format of credentials in file '%s': %s",
                       credentials_path,
                       secret_key_result.status().error_message());
    }
    return Aws::Auth::AWSCredentials(key_id_result.ValueOrDie().c_str(),
                                     secret_key_result.ValueOrDie().c_str());
  }

  // Get default credentials.
  Aws::Auth::DefaultAWSCredentialsProviderChain provider_chain;
  return provider_chain.GetAWSCredentials();
}

}  // namespace


bool AwsKmsClient::aws_api_is_initialized_;
absl::Mutex AwsKmsClient::aws_api_init_mutex_;

// static
void AwsKmsClient::InitAwsApi() {
  absl::MutexLock lock(&aws_api_init_mutex_);
  if (aws_api_is_initialized_) return;
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

// static
StatusOr<std::unique_ptr<AwsKmsClient>>
AwsKmsClient::New(absl::string_view key_uri,
                  absl::string_view credentials_path) {
  if (!aws_api_is_initialized_) InitAwsApi();
  std::unique_ptr<AwsKmsClient> client(new AwsKmsClient());

  // Read credentials.
  auto credentials_result = GetAwsCredentials(credentials_path);
  if (!credentials_result.ok()) {
    return credentials_result.status();
  }
  client->credentials_ = credentials_result.ValueOrDie();

  // If a specific key is given, create an AWS KMSClient.
  if (!key_uri.empty()) {
    client->key_arn_ = GetKeyArn(key_uri);
    if (client->key_arn_.empty()) {
      return ToStatusF(util::error::INVALID_ARGUMENT, "Key '%s' not supported",
                       key_uri);
    }
    auto config_result = GetAwsClientConfig(client->key_arn_);
    if (!config_result.ok()) return config_result.status();
    // Create AWS KMSClient.
    client->aws_client_ = Aws::MakeShared<Aws::KMS::KMSClient>(
        kAwsCryptoAllocationTag,
        client->credentials_,
        config_result.ValueOrDie());
  }
  return std::move(client);
}

bool AwsKmsClient::DoesSupport(absl::string_view key_uri) const {
  if (!key_arn_.empty()) {
    return key_arn_ == GetKeyArn(key_uri);
  }
  return !GetKeyArn(key_uri).empty();
}

StatusOr<std::unique_ptr<Aead>>
AwsKmsClient::GetAead(absl::string_view key_uri) const {
  if (!DoesSupport(key_uri)) {
    if (!key_arn_.empty()) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "This client is bound to '%s', and cannot use key '%s'.",
                       key_arn_, key_uri);
    } else {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "This client does not support key '%s'.", key_uri);
    }
  }
  if (!key_arn_.empty()) {  // This client is bound to a specific key.
    return AwsKmsAead::New(key_arn_, aws_client_);
  } else {  // Create an AWS KMSClient for the given key.
    auto key_arn = GetKeyArn(key_uri);
    auto config_result = GetAwsClientConfig(key_arn);
    if (!config_result.ok()) return config_result.status();
    auto aws_client = Aws::MakeShared<Aws::KMS::KMSClient>(
        kAwsCryptoAllocationTag, credentials_, config_result.ValueOrDie());
    return AwsKmsAead::New(key_arn, aws_client);
  }
}

Status AwsKmsClient::RegisterNewClient(absl::string_view key_uri,
                                       absl::string_view credentials_path) {
  auto client_result = AwsKmsClient::New(key_uri, credentials_path);
  if (!client_result.ok()) {
    return client_result.status();
  }

  return KmsClients::Add(std::move(client_result.ValueOrDie()));
}

}  // namespace awskms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
