// Copyright 2024 Google LLC
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

#ifndef TINK_INTEGRATION_GCPKMS_GCP_KMS_PUBLIC_KEY_SIGN_H_
#define TINK_INTEGRATION_GCPKMS_GCP_KMS_PUBLIC_KEY_SIGN_H_

#include <memory>

#include "absl/base/nullability.h"
#include "absl/strings/string_view.h"
#include "third_party/cloud_cpp/google/cloud/kms/v1/key_management_client.h"
#include "tink/public_key_sign.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {

// Creates a new PublicKeySign object that is bound to the key specified
// in `key_name`, and that uses the `kms_client` to communicate with the KMS.
//
// Valid values for `key_name` have the following format:
//    projects/*/locations/*/keyRings/*/cryptoKeys/*/cryptoKeyVersions/*.
// See https://cloud.google.com/kms/docs/object-hierarchy for more info.
crypto::tink::util::StatusOr<std::unique_ptr<PublicKeySign>>
CreateGcpKmsPublicKeySign(
    absl::string_view key_name,
    absl::Nonnull<
        std::shared_ptr<google::cloud::kms_v1::KeyManagementServiceClient>>
        kms_client);

}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTEGRATION_GCPKMS_GCP_KMS_PUBLIC_KEY_SIGN_H_
