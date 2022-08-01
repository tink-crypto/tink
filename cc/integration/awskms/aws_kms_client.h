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

#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "aws/core/auth/AWSCredentialsProvider.h"
#include "aws/kms/KMSClient.h"
#include "tink/aead.h"
#include "tink/kms_client.h"
#include "tink/kms_clients.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace integration {
namespace awskms {

// AwsKmsClient is an implementation of KmsClient for
// <a href="https://aws.amazon.com/kms/">AWS KMS</a>
class AwsKmsClient : public crypto::tink::KmsClient {
 public:
  // Creates a new AwsKmsClient that is bound to the key specified in `key_uri`,
  // if not empty, and that uses the credentials in `credentials_path`, if not
  // empty, or the default ones to authenticate to the KMS.
  //
  // If `key_uri` is empty, then the client is not bound to any particular key.
  static crypto::tink::util::StatusOr<std::unique_ptr<AwsKmsClient>>
  New(absl::string_view key_uri, absl::string_view credentials_path);

  // Creates a new client and registers it in KMSClients.
  static crypto::tink::util::Status RegisterNewClient(
      absl::string_view key_uri, absl::string_view credentials_path);

  // Returns true if: (1) `key_uri` is a valid AWS KMS key URI, and (2) the
  // resulting AWS key ARN is equals to key_arn_, in case this client is bound
  // to a specific key.
  bool DoesSupport(absl::string_view key_uri) const override;

  // Returns an Aead-primitive backed by KMS key specified by `key_uri`,
  // provided that this KmsClient does support `key_uri`.
  crypto::tink::util::StatusOr<std::unique_ptr<Aead>>
  GetAead(absl::string_view key_uri) const override;

 private:
  AwsKmsClient(absl::string_view key_arn, Aws::Auth::AWSCredentials credentials)
      : key_arn_(key_arn), credentials_(credentials) {}
  AwsKmsClient(Aws::Auth::AWSCredentials credentials)
      : credentials_(credentials) {}

  // Initializes AWS API.
  static void InitAwsApi();
  static bool aws_api_is_initialized_;
  static absl::Mutex aws_api_init_mutex_;

  std::string key_arn_;
  Aws::Auth::AWSCredentials credentials_;
  std::shared_ptr<Aws::KMS::KMSClient> aws_client_;
};

}  // namespace awskms
}  // namespace integration
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTEGRATION_AWSKMS_AWS_KMS_CLIENT_H_
