// Copyright 2018 Google LLC
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

#ifndef AWSKMS_AWS_KMS_AEAD_H_
#define AWSKMS_AWS_KMS_AEAD_H_

#include "absl/strings/string_view.h"
#include "aws/kms/KMSClient.h"
#include "tink/aead.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace integration {
namespace awskms {

// AwsKmsAead is an implementation of AEAD that forwards
// encryption/decryption requests to a key managed by
// <a href="https://aws.amazon.com/kms/">AWS KMS</a>.
class AwsKmsAead : public Aead {
 public:
  // Creates a new AwsKmsAead that is bound to the key specified in 'key_arn',
  // and that uses the given client when communicating with the KMS.
  static crypto::tink::util::StatusOr<std::unique_ptr<Aead>>
  New(absl::string_view key_arn,
      std::shared_ptr<Aws::KMS::KMSClient> aws_client);

  crypto::tink::util::StatusOr<std::string> Encrypt(
      absl::string_view plaintext,
      absl::string_view associated_data) const override;

  crypto::tink::util::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext,
      absl::string_view associated_data) const override;

  virtual ~AwsKmsAead() {}

 private:
  AwsKmsAead(absl::string_view key_arn,
             std::shared_ptr<Aws::KMS::KMSClient> aws_client);
  std::string key_arn_;  // The location of a crypto key in AWS KMS.
  std::shared_ptr<Aws::KMS::KMSClient> aws_client_;
};


}  // namespace awskms
}  // namespace integration
}  // namespace tink
}  // namespace crypto

#endif  // AWSKMS_AWS_KMS_AEAD_H_
