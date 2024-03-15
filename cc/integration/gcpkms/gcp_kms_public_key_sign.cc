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

#include "tink/integration/gcpkms/gcp_kms_public_key_sign.h"

#include <cstdint>
#include <memory>
#include <string>

#include "absl/base/nullability.h"
#include "absl/crc/crc32c.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "third_party/cloud_cpp/google/cloud/kms/v1/key_management_client.h"
#include "third_party/cloud_cpp/google/cloud/status_or.h"
#include "openssl/base.h"
#include "openssl/digest.h"
#include "third_party/re2/re2.h"
#include "tink/public_key_sign.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace {

using ::crypto::tink::util::StatusOr;
using ::google::cloud::kms::v1::AsymmetricSignRequest;
using ::google::cloud::kms::v1::AsymmetricSignResponse;
using ::google::cloud::kms::v1::CryptoKeyVersion;
using ::google::cloud::kms::v1::Digest;
using ::google::cloud::kms::v1::GetPublicKeyRequest;
using ::google::cloud::kms::v1::ProtectionLevel;
using ::google::cloud::kms::v1::PublicKey;
using ::google::cloud::kms_v1::KeyManagementServiceClient;

// Maximum size of the data that can be signed.
static constexpr int kMaxSignDataSize = 64 * 1024;
static constexpr LazyRE2 kKmsKeyNameFormat = {
    "projects/[^/]+/locations/[^/]+/keyRings/[^/]+/cryptoKeys/[^/]+/"
    "cryptoKeyVersions/.*"};

// Some AsymmetricSign algorithms require data as input and some other
// operate on a digest of the data. This method determines if data itself is
// required for signing and returns true if so.
bool RequiresDataForSign(CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm,
                         ProtectionLevel protection_level) {
  // Operate on the data if the algorithm is one of the followings:
  switch (algorithm) {
    case CryptoKeyVersion::RSA_SIGN_RAW_PKCS1_2048:
    case CryptoKeyVersion::RSA_SIGN_RAW_PKCS1_3072:
    case CryptoKeyVersion::RSA_SIGN_RAW_PKCS1_4096:
      return true;
    default:
      break;
  }

  // or the protection level is one of the followings:
  switch (protection_level) {
    case ProtectionLevel::EXTERNAL:
    case ProtectionLevel::EXTERNAL_VPC:
      return true;
    default:
      break;
  }

  return false;
}

// Finds out and returns the proper DigestCase for the given algorithm.
StatusOr<Digest::DigestCase> GetDigestFromAlgorithm(
    CryptoKeyVersion::CryptoKeyVersionAlgorithm algorithm) {
  switch (algorithm) {
    case CryptoKeyVersion::EC_SIGN_P256_SHA256:
    case CryptoKeyVersion::EC_SIGN_SECP256K1_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PSS_2048_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PSS_3072_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PKCS1_2048_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PKCS1_3072_SHA256:
    case CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA256:
      return Digest::DigestCase::kSha256;
    case CryptoKeyVersion::EC_SIGN_P384_SHA384:
      return Digest::DigestCase::kSha384;
    case CryptoKeyVersion::RSA_SIGN_PSS_4096_SHA512:
    case CryptoKeyVersion::RSA_SIGN_PKCS1_4096_SHA512:
      return Digest::DigestCase::kSha512;
    default:
      return absl::InternalError(absl::StrCat(
          "The given algorithm ",
          CryptoKeyVersion::CryptoKeyVersionAlgorithm_Name(algorithm),
          " does not support digests."));
  }
}

StatusOr<std::string> ComputeDigest(absl::string_view data,
                                    Digest::DigestCase digest_case) {
  const EVP_MD* md;
  switch (digest_case) {
    case Digest::kSha256:
      md = EVP_sha256();
      break;
    case Digest::kSha384:
      md = EVP_sha384();
      break;
    case Digest::kSha512:
      md = EVP_sha512();
      break;
    default:
      return util::Status(absl::StatusCode::kInternal,
                          absl::StrCat("Invalid DigestCase: ", digest_case));
  }

  unsigned int digest_size;
  uint8_t digest[EVP_MAX_MD_SIZE];
  if (EVP_Digest(data.data(), data.size(), digest, &digest_size, md,
                 /*impl=*/nullptr) != 1) {
    return util::Status(absl::StatusCode::kInternal,
                        "Error computing the digest.");
  }
  return std::string(reinterpret_cast<char*>(digest), digest_size);
}

// Builds and returns an AsymmetricSignRequest.
// It determines whether data or digest is required for signing,
// and prepares the request accordingly.
StatusOr<AsymmetricSignRequest> BuildAsymmetricSignRequest(
    absl::string_view key_name, absl::string_view data, PublicKey public_key) {
  AsymmetricSignRequest request;
  request.set_name(key_name);
  if (RequiresDataForSign(public_key.algorithm(),
                          public_key.protection_level())) {
    request.set_data(data);
    request.mutable_data_crc32c()->set_value(
        static_cast<uint32_t>(absl::ComputeCrc32c(data)));
    return request;
  }

  // Digest is needed; compute it.
  StatusOr<Digest::DigestCase> digest_case =
      GetDigestFromAlgorithm(public_key.algorithm());
  if (!digest_case.ok()) {
    return digest_case.status();
  }

  StatusOr<std::string> digest_string = ComputeDigest(data, *digest_case);
  if (!digest_string.ok()) {
    return digest_string.status();
  }

  switch (*digest_case) {
    case Digest::kSha256:
      request.mutable_digest()->set_sha256(*digest_string);
      break;
    case Digest::kSha384:
      request.mutable_digest()->set_sha384(*digest_string);
      break;
    case Digest::kSha512:
      request.mutable_digest()->set_sha512(*digest_string);
      break;
    default:
      return util::Status(absl::StatusCode::kInternal,
                          absl::StrCat("Invalid DigestCase: ", *digest_case));
  }
  request.mutable_digest_crc32c()->set_value(
      static_cast<uint32_t>(absl::ComputeCrc32c(*digest_string)));

  return request;
}

// GcpKmsPublicKeySign is an implementation of PublicKeySign that forwards
// asymmetric sign requests to Google Cloud KMS (https://cloud.google.com/kms/).
class GcpKmsPublicKeySign : public PublicKeySign {
 public:
  crypto::tink::util::StatusOr<std::string> Sign(
      absl::string_view data) const override;

  GcpKmsPublicKeySign(
      absl::string_view key_name, google::cloud::kms::v1::PublicKey public_key,
      std::shared_ptr<google::cloud::kms_v1::KeyManagementServiceClient>
          kms_client)
      : key_name_(key_name), public_key_(public_key), kms_client_(kms_client) {}

 private:
  // The location of a crypto key in GCP KMS.
  std::string key_name_;
  google::cloud::kms::v1::PublicKey public_key_;
  std::shared_ptr<google::cloud::kms_v1::KeyManagementServiceClient>
      kms_client_;
};

StatusOr<std::string> GcpKmsPublicKeySign::Sign(absl::string_view data) const {
  if (data.size() > kMaxSignDataSize) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("The input data (", data.size(),
                     " bytes) is larger than the allowed limit (",
                     kMaxSignDataSize, " bytes)."));
  }

  // Build the sign request.
  StatusOr<AsymmetricSignRequest> request =
      BuildAsymmetricSignRequest(key_name_, data, public_key_);
  if (!request.ok()) {
    return request.status();
  }

  // Send the request to KMS for signing.
  google::cloud::StatusOr<AsymmetricSignResponse> response =
      kms_client_->AsymmetricSign(*request);
  if (!response.ok()) {
    return util::Status(absl::StatusCode::kInternal,
                        absl::StrCat("GCP KMS AsymmetricSign failed: ",
                                     response.status().message()));
  }
  // Perform integrity checks.
  if (response->name() != key_name_) {
    return util::Status(absl::StatusCode::kInternal,
                        absl::StrCat("The key name in the response does not "
                                     "match the requested key name.",
                                     response.status().message()));
  }
  if (!response->verified_data_crc32c() &&
      !response->verified_digest_crc32c()) {
    return util::Status(absl::StatusCode::kInternal,
                        absl::StrCat("Checking the input checksum failed.",
                                     response.status().message()));
  }
  uint32_t given_crc32c =
      static_cast<uint32_t>(response->signature_crc32c().value());
  uint32_t computed_crc32c =
      static_cast<uint32_t>(absl::ComputeCrc32c(response->signature()));
  if (computed_crc32c != given_crc32c) {
    return util::Status(absl::StatusCode::kInternal,
                        absl::StrCat("Signature checksum mismatch.",
                                     response.status().message()));
  }
  // Return the signature.
  return response->signature();
}
}  // namespace

StatusOr<std::unique_ptr<PublicKeySign>> CreateGcpKmsPublicKeySign(
    absl::string_view key_name,
    absl::Nonnull<std::shared_ptr<KeyManagementServiceClient>> kms_client) {
  if (!RE2::FullMatch(key_name, *kKmsKeyNameFormat)) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat(key_name, " does not match the KMS key name format: ",
                     kKmsKeyNameFormat->pattern()));
  }
  if (kms_client == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "KMS client cannot be null.");
  }
  // Retrieve the related public key from KMS, that contains information on
  // how to prepare the later AsymmetricSign requests.
  GetPublicKeyRequest request;
  request.set_name(key_name);
  google::cloud::StatusOr<PublicKey> response =
      kms_client->GetPublicKey(request);
  if (!response.ok()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("GCP KMS GetPublicKey failed: ",
                                     response.status().message()));
  }
  return absl::make_unique<GcpKmsPublicKeySign>(key_name, *response,
                                                kms_client);
}

}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
