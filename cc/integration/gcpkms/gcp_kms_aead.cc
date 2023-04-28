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

#include "tink/integration/gcpkms/gcp_kms_aead.h"

#include <memory>
#include <string>

#include "google/cloud/kms/v1/service.grpc.pb.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {

using ::google::cloud::kms::v1::DecryptRequest;
using ::google::cloud::kms::v1::DecryptResponse;
using ::google::cloud::kms::v1::EncryptRequest;
using ::google::cloud::kms::v1::EncryptResponse;
using ::google::cloud::kms::v1::KeyManagementService;

util::StatusOr<std::unique_ptr<Aead>> GcpKmsAead::New(
    absl::string_view key_name,
    std::shared_ptr<KeyManagementService::Stub> kms_stub) {
  if (key_name.empty()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Key URI cannot be empty.");
  }
  if (kms_stub == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "KMS stub cannot be null.");
  }
  return absl::WrapUnique(new GcpKmsAead(key_name, kms_stub));
}

util::StatusOr<std::string> GcpKmsAead::Encrypt(
    absl::string_view plaintext, absl::string_view associated_data) const {
  EncryptRequest req;
  req.set_name(key_name_);
  req.set_plaintext(std::string(plaintext));
  req.set_additional_authenticated_data(std::string(associated_data));

  EncryptResponse resp;
  grpc::ClientContext context;
  context.AddMetadata("x-goog-request-params",
                      absl::StrCat("name=", key_name_));

  grpc::Status status = kms_stub_->Encrypt(&context, req, &resp);

  if (!status.ok()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("GCP KMS encryption failed: ", status.error_message()));
  }
  return resp.ciphertext();
}

util::StatusOr<std::string> GcpKmsAead::Decrypt(
    absl::string_view ciphertext, absl::string_view associated_data) const {
  DecryptRequest req;
  req.set_name(key_name_);
  req.set_ciphertext(std::string(ciphertext));
  req.set_additional_authenticated_data(std::string(associated_data));

  DecryptResponse resp;
  grpc::ClientContext context;
  context.AddMetadata("x-goog-request-params",
                      absl::StrCat("name=", key_name_));

  grpc::Status status = kms_stub_->Decrypt(&context, req, &resp);

  if (!status.ok()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("GCP KMS encryption failed: ", status.error_message()));
  }
  return resp.plaintext();
}

}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
