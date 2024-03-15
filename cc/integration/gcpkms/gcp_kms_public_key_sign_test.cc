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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/crc/crc32c.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "third_party/cloud_cpp/google/cloud/kms/v1/key_management_client.h"
#include "third_party/cloud_cpp/google/cloud/kms/v1/mocks/mock_key_management_connection.h"
#include "third_party/cloud_cpp/google/cloud/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace {

namespace kmsV1 = ::google::cloud::kms::v1;

using ::crypto::tink::test::DummyPublicKeySign;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::google::cloud::Status;
using ::google::cloud::StatusOr;
using ::google::cloud::kms_v1::KeyManagementServiceClient;
using ::google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection;
using ::testing::HasSubstr;

constexpr absl::string_view kData = "data for signing";
constexpr absl::string_view kDigest = "digest for signing";
constexpr absl::string_view kKeyNameRequiresData1 =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/1";
constexpr absl::string_view kKeyNameRequiresData2 =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/2";
constexpr absl::string_view kKeyNameRequiresDigest =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/3";
constexpr absl::string_view kKeyNameErrorGetPublicKey =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/4";
constexpr absl::string_view kKeyNameErrorAsymmetricSign =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/5";
constexpr absl::string_view kKeyNameErrorCrc32c =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/6";
constexpr absl::string_view kKeyNameErrorCrc32cNotVerified =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/7";
constexpr absl::string_view kKeyNameErrorWrongKeyName =
    "projects/P1/locations/L1/keyRings/R1/cryptoKeys/K1/cryptoKeyVersions/8";

class TestGcpKmsPublicKeySign : public testing::Test {
 public:
  TestGcpKmsPublicKeySign()
      : mock_connection_(
            std::make_shared<MockKeyManagementServiceConnection>()),
        kms_client_(
            std::make_shared<KeyManagementServiceClient>(mock_connection_)) {}

  void ExpectSign(const DummyPublicKeySign& signer, int times) {
    EXPECT_CALL(*mock_connection_, AsymmetricSign)
        .Times(times)
        .WillRepeatedly([&](kmsV1::AsymmetricSignRequest const& request)
                            -> StatusOr<kmsV1::AsymmetricSignResponse> {
          if (request.name() == kKeyNameErrorAsymmetricSign) {
            return Status(google::cloud::StatusCode::kInternal,
                          "Internal error");
          }

          // Prepare response based on the given data/digest.
          kmsV1::AsymmetricSignResponse response;
          response.set_name(request.name());
          if (request.has_digest()) {
            response.set_verified_digest_crc32c(true);
            response.set_signature(*signer.Sign(kDigest));
          } else {
            response.set_verified_data_crc32c(true);
            response.set_signature(*signer.Sign(kData));
          }
          response.mutable_signature_crc32c()->set_value(
              static_cast<uint32_t>(absl::ComputeCrc32c(response.signature())));

          // Manipulate the key name value for the: kKeyNameErrorWrongKeyName.
          if (request.name() == kKeyNameErrorWrongKeyName) {
            response.set_name(kKeyNameRequiresData1);
          }
          // Manipulate the crc32c value for the case: kKeyNameErrorCrc32c.
          if (request.name() == kKeyNameErrorCrc32c) {
            response.mutable_signature_crc32c()->set_value(1);
          }
          // Crc32c check failed, set both fields to false, for the case:
          // kKeyNameErrorCrc32cNotVerified.
          if (request.name() == kKeyNameErrorCrc32cNotVerified) {
            response.set_verified_data_crc32c(false);
            response.set_verified_digest_crc32c(false);
          }

          return StatusOr<kmsV1::AsymmetricSignResponse>(response);
        });
  }

  void ExpectGetPublicKey(int times) {
    EXPECT_CALL(*mock_connection_, GetPublicKey)
        .Times(times)
        .WillRepeatedly([&](kmsV1::GetPublicKeyRequest const& request)
                            -> StatusOr<kmsV1::PublicKey> {
          kmsV1::PublicKey response;
          if (request.name() == kKeyNameRequiresData1 ||
              request.name() == kKeyNameErrorAsymmetricSign ||
              request.name() == kKeyNameErrorCrc32c ||
              request.name() == kKeyNameErrorCrc32cNotVerified ||
              request.name() == kKeyNameErrorWrongKeyName) {
            // This operates on the data.
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::RSA_SIGN_RAW_PKCS1_2048);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
          } else if (request.name() == kKeyNameRequiresData2) {
            // This operates on the data.
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::RSA_SIGN_PSS_2048_SHA256);
            response.set_protection_level(kmsV1::ProtectionLevel::EXTERNAL);
          } else if (request.name() == kKeyNameRequiresDigest) {
            // This operates on the digest.
            response.set_algorithm(
                kmsV1::CryptoKeyVersion::RSA_SIGN_PSS_2048_SHA256);
            response.set_protection_level(kmsV1::ProtectionLevel::SOFTWARE);
          } else if (request.name() == kKeyNameErrorGetPublicKey) {
            return Status(google::cloud::StatusCode::kInternal,
                          "Internal error");
          }
          return StatusOr<kmsV1::PublicKey>(response);
        });
  }

 protected:
  std::shared_ptr<MockKeyManagementServiceConnection> mock_connection_;
  std::shared_ptr<KeyManagementServiceClient> kms_client_;
};

TEST_F(TestGcpKmsPublicKeySign, NullKmsClientFails) {
  EXPECT_THAT(
      CreateGcpKmsPublicKeySign(kKeyNameRequiresData1, nullptr).status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("KMS client cannot be null")));
}

TEST_F(TestGcpKmsPublicKeySign, EmptyKeyNameFails) {
  EXPECT_THAT(CreateGcpKmsPublicKeySign("", kms_client_).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("does not match")));
}

TEST_F(TestGcpKmsPublicKeySign, WrongKeyNameFails) {
  EXPECT_THAT(CreateGcpKmsPublicKeySign("Wrong/Key/Name", kms_client_).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("does not match")));
}

TEST_F(TestGcpKmsPublicKeySign, GetPublicKeyFails) {
  ExpectGetPublicKey(1);
  auto kmsSigner =
      CreateGcpKmsPublicKeySign(kKeyNameErrorGetPublicKey, kms_client_);
  EXPECT_THAT(kmsSigner.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("GCP KMS GetPublicKey failed")));
}

TEST_F(TestGcpKmsPublicKeySign, AsymmetricSignFails) {
  DummyPublicKeySign signer = DummyPublicKeySign(kKeyNameErrorAsymmetricSign);
  ExpectGetPublicKey(1);
  ExpectSign(signer, /*times*/ 1);
  auto kmsSigner =
      CreateGcpKmsPublicKeySign(kKeyNameErrorAsymmetricSign, kms_client_);
  EXPECT_THAT(kmsSigner.status(), IsOk());
  EXPECT_THAT((*kmsSigner)->Sign(kData).status(),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("GCP KMS AsymmetricSign failed")));
}

TEST_F(TestGcpKmsPublicKeySign, WrongInputCrc32cFails) {
  DummyPublicKeySign signer =
      DummyPublicKeySign(kKeyNameErrorCrc32cNotVerified);
  ExpectGetPublicKey(1);
  ExpectSign(signer, /*times*/ 1);
  auto kmsSigner =
      CreateGcpKmsPublicKeySign(kKeyNameErrorCrc32cNotVerified, kms_client_);
  EXPECT_THAT(kmsSigner.status(), IsOk());
  EXPECT_THAT((*kmsSigner)->Sign(kData).status(),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("Checking the input checksum failed.")));
}

TEST_F(TestGcpKmsPublicKeySign, WrongSignatureCrc32cFails) {
  DummyPublicKeySign signer = DummyPublicKeySign(kKeyNameErrorCrc32c);
  ExpectGetPublicKey(1);
  ExpectSign(signer, /*times*/ 1);
  auto kmsSigner = CreateGcpKmsPublicKeySign(kKeyNameErrorCrc32c, kms_client_);
  EXPECT_THAT(kmsSigner.status(), IsOk());
  EXPECT_THAT((*kmsSigner)->Sign(kData).status(),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("Signature checksum mismatch")));
}

TEST_F(TestGcpKmsPublicKeySign, LargeInputDataFails) {
  ExpectGetPublicKey(1);
  std::string large_data(64 * 1024 + 1, 'A');
  auto kmsSigner =
      CreateGcpKmsPublicKeySign(kKeyNameRequiresData1, kms_client_);
  EXPECT_THAT(kmsSigner.status(), IsOk());
  EXPECT_THAT(
      (*kmsSigner)->Sign(large_data).status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("larger than")));
}

TEST_F(TestGcpKmsPublicKeySign, WrongKeyNameInTheResponseFails) {
  DummyPublicKeySign signer = DummyPublicKeySign(kKeyNameErrorWrongKeyName);
  ExpectGetPublicKey(1);
  ExpectSign(signer, /*times*/ 1);
  auto kmsSigner =
      CreateGcpKmsPublicKeySign(kKeyNameErrorWrongKeyName, kms_client_);
  EXPECT_THAT(kmsSigner.status(), IsOk());
  EXPECT_THAT((*kmsSigner)->Sign(kData).status(),
              StatusIs(absl::StatusCode::kInternal,
                       HasSubstr("does not match the requested key name")));
}

TEST_F(TestGcpKmsPublicKeySign, PublicKeySignDataOnAlgorithmSuccess) {
  DummyPublicKeySign signer = DummyPublicKeySign(kKeyNameRequiresData1);
  ExpectGetPublicKey(1);
  ExpectSign(signer, /*times*/ 1);
  auto kmsSigner =
      CreateGcpKmsPublicKeySign(kKeyNameRequiresData1, kms_client_);
  EXPECT_THAT(kmsSigner.status(), IsOk());
  EXPECT_THAT((*kmsSigner)->Sign(kData), IsOkAndHolds(*signer.Sign(kData)));
}

TEST_F(TestGcpKmsPublicKeySign, PublicKeySignDataOnProtectionLevelSuccess) {
  DummyPublicKeySign signer = DummyPublicKeySign(kKeyNameRequiresData2);
  ExpectGetPublicKey(1);
  ExpectSign(signer, /*times*/ 1);
  auto kmsSigner =
      CreateGcpKmsPublicKeySign(kKeyNameRequiresData2, kms_client_);
  EXPECT_THAT(kmsSigner.status(), IsOk());
  EXPECT_THAT((*kmsSigner)->Sign(kData), IsOkAndHolds(*signer.Sign(kData)));
}

TEST_F(TestGcpKmsPublicKeySign, PublicKeySignDigestSuccess) {
  DummyPublicKeySign signer = DummyPublicKeySign(kKeyNameRequiresDigest);
  ExpectGetPublicKey(1);
  ExpectSign(signer, /*times*/ 1);
  auto kmsSigner =
      CreateGcpKmsPublicKeySign(kKeyNameRequiresDigest, kms_client_);
  EXPECT_THAT(kmsSigner.status(), IsOk());
  EXPECT_THAT((*kmsSigner)->Sign(kData), IsOkAndHolds(*signer.Sign(kDigest)));
}

}  // namespace
}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
