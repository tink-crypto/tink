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

#ifndef TINK_INTEGRATION_GCPKMS_GCP_KMS_AEAD_H_
#define TINK_INTEGRATION_GCPKMS_GCP_KMS_AEAD_H_

#include <memory>
#include <string>

#include "google/cloud/kms/v1/service.grpc.pb.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {

// GcpKmsAead is an implementation of AEAD that forwards encryption/decryption
// requests to a key managed by the Google Cloud KMS
// (https://cloud.google.com/kms/).
class GcpKmsAead : public Aead {
 public:
  // Move only.
  GcpKmsAead(GcpKmsAead&& other) = default;
  GcpKmsAead& operator=(GcpKmsAead&& other) = default;
  GcpKmsAead(const GcpKmsAead&) = delete;
  GcpKmsAead& operator=(const GcpKmsAead&) = delete;

  // Creates a new GcpKmsAead that is bound to the key specified in `key_name`,
  // and that uses the channel when communicating with the KMS.
  //
  // Valid values for `key_name` have the following format:
  //    projects/*/locations/*/keyRings/*/cryptoKeys/*.
  // See https://cloud.google.com/kms/docs/object-hierarchy for more info.
  static crypto::tink::util::StatusOr<std::unique_ptr<Aead>> New(
      absl::string_view key_name,
      std::shared_ptr<google::cloud::kms::v1::KeyManagementService::Stub>
          kms_stub);

  crypto::tink::util::StatusOr<std::string> Encrypt(
      absl::string_view plaintext,
      absl::string_view associated_data) const override;

  crypto::tink::util::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext,
      absl::string_view associated_data) const override;

 private:
  explicit GcpKmsAead(
      absl::string_view key_name,
      std::shared_ptr<google::cloud::kms::v1::KeyManagementService::Stub>
          kms_stub)
      : key_name_(key_name), kms_stub_(kms_stub) {}

  // The location of a crypto key in GCP KMS.
  std::string key_name_;
  std::shared_ptr<google::cloud::kms::v1::KeyManagementService::Stub> kms_stub_;
};

}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTEGRATION_GCPKMS_GCP_KMS_AEAD_H_
