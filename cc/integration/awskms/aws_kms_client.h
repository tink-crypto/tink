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

#ifndef TINK_INTEGRATION_AWSKMS_AWS_KMS_CLIENT_H_
#define TINK_INTEGRATION_AWSKMS_AWS_KMS_CLIENT_H_

#include <memory>

#include "aws/core/auth/AWSCredentialsProvider.h"
#include "aws/kms/KMSClient.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "tink/aead.h"
#include "tink/kms_client.h"
#include "tink/kms_clients.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace integration {
namespace awskms {

// AwsKmsClient is an implementation of KmsClient for AWS KMS
// (https://aws.amazon.com/kms/).
class AwsKmsClient : public crypto::tink::KmsClient {
 public:
  // Move only.
  AwsKmsClient(AwsKmsClient&& other) = default;
  AwsKmsClient& operator=(AwsKmsClient&& other) = default;
  AwsKmsClient(const AwsKmsClient&) = delete;
  AwsKmsClient& operator=(const AwsKmsClient&) = delete;

  // Creates a new AwsKmsClient that is bound to the key specified in `key_uri`,
  // if not empty, and that uses the credentials in `credentials_path`, if not
  // empty, or the default ones to authenticate to the KMS.
  //
  // If `key_uri` is empty, then the client is not bound to any particular key.
  static crypto::tink::util::StatusOr<std::unique_ptr<AwsKmsClient>> New(
      absl::string_view key_uri, absl::string_view credentials_path);

  // Creates a new client and adds it to the global list of KMSClients.
  //
  // This function should only be called on startup and not on every operation.
  // Avoid registering a client more than once.
  //
  // It is often not necessary to use this function.  Instead, you can call
  // AwsKmsAead::New to directly create an Aead object without creating or
  // registering a client.
  static crypto::tink::util::Status RegisterNewClient(
      absl::string_view key_uri, absl::string_view credentials_path);

  // Returns true if: (1) `key_uri` is a valid AWS KMS key URI, and (2) the
  // resulting AWS key ARN is equals to key_arn_, in case this client is bound
  // to a specific key.
  bool DoesSupport(absl::string_view key_uri) const override;

  crypto::tink::util::StatusOr<std::unique_ptr<Aead>> GetAead(
      absl::string_view key_uri) const override;

 private:
  AwsKmsClient(absl::string_view key_arn, Aws::Auth::AWSCredentials credentials)
      : key_arn_(key_arn), credentials_(credentials) {}
  AwsKmsClient(Aws::Auth::AWSCredentials credentials)
      : credentials_(credentials) {}

  std::string key_arn_;
  Aws::Auth::AWSCredentials credentials_;
  std::shared_ptr<Aws::KMS::KMSClient> aws_client_;
};

}  // namespace awskms
}  // namespace integration
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTEGRATION_AWSKMS_AWS_KMS_CLIENT_H_
