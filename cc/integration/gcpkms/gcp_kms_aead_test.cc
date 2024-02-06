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

#include "tink/integration/gcpkms/gcp_kms_aead.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "third_party/cloud_cpp/google/cloud/kms/v1/key_management_client.h"
#include "third_party/cloud_cpp/google/cloud/kms/v1/mocks/mock_key_management_connection.h"
#include "third_party/cloud_cpp/google/cloud/status.h"
#include "tink/aead.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {

namespace kmsV1 = ::google::cloud::kms::v1;
using ::crypto::tink::test::DummyAead;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::google::cloud::Status;
using ::google::cloud::StatusOr;
using ::google::cloud::kms_v1::KeyManagementServiceClient;
using ::google::cloud::kms_v1_mocks::MockKeyManagementServiceConnection;
using ::testing::HasSubstr;

constexpr absl::string_view kAad1 = "additional authenticated data1";
constexpr absl::string_view kAad2 = "additional authenticated data2";
constexpr absl::string_view kPlaintext = "plaintext";
constexpr absl::string_view kKeyName =
    "projects/project1/locations/global/keyRings/key1/cryptoKeys/aead-key";

class TestGcpKmsAead : public testing::Test {
 public:
  TestGcpKmsAead()
      : mock_connection_(
            std::make_shared<MockKeyManagementServiceConnection>()),
        kms_client_(
            std::make_shared<google::cloud::kms_v1::KeyManagementServiceClient>(
                mock_connection_)) {}

  void ExpectEncrypt(const DummyAead& aead, int times) {
    EXPECT_CALL(*mock_connection_, Encrypt)
        .Times(times)
        .WillRepeatedly([&](kmsV1::EncryptRequest const& request)
                            -> StatusOr<kmsV1::EncryptResponse> {
          auto ciphertext = aead.Encrypt(
              request.plaintext(), request.additional_authenticated_data());
          kmsV1::EncryptResponse response;
          response.set_ciphertext(*ciphertext);
          return StatusOr<kmsV1::EncryptResponse>(response);
        });
  }

  void ExpectDecrypt(const DummyAead& aead, int times) {
    EXPECT_CALL(*mock_connection_, Decrypt)
        .Times(times)
        .WillRepeatedly([&](kmsV1::DecryptRequest const& request)
                            -> StatusOr<kmsV1::DecryptResponse> {
          util::StatusOr<std::string> plaintext = aead.Decrypt(
              request.ciphertext(), request.additional_authenticated_data());
          if (!plaintext.ok()) {
            return Status(google::cloud::StatusCode::kInvalidArgument,
                          "Decryption failed.");
          }

          kmsV1::DecryptResponse response;
          response.set_plaintext(*plaintext);
          return StatusOr<kmsV1::DecryptResponse>(response);
        });
  }

 protected:
  std::shared_ptr<MockKeyManagementServiceConnection> mock_connection_;
  std::shared_ptr<KeyManagementServiceClient> kms_client_;
};

TEST_F(TestGcpKmsAead, FailsWithNullKmsClient) {
  EXPECT_THAT(NewGcpKmsAead(kKeyName, nullptr).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("KMS client cannot be null")));
}

TEST_F(TestGcpKmsAead, FailsWithEmptyKeyName) {
  EXPECT_THAT(NewGcpKmsAead("", kms_client_).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("does not match")));
}

TEST_F(TestGcpKmsAead, FailsWithWrongKeyName) {
  EXPECT_THAT(NewGcpKmsAead("Wrong/Key/Name", kms_client_).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("does not match")));
}

TEST_F(TestGcpKmsAead, EncryptionDecryptionWorks) {
  auto kmsAead = NewGcpKmsAead(kKeyName, kms_client_);
  EXPECT_THAT(kmsAead.status(), IsOk());
  DummyAead aead = DummyAead(kKeyName);

  // There are 9 encryption calls and 3 decryption calls in total.
  ExpectEncrypt(aead, 9);
  ExpectDecrypt(aead, 3);
  EXPECT_THAT(kmsAead->get()->Encrypt(kPlaintext, kAad1),
              IsOkAndHolds(*aead.Encrypt(kPlaintext, kAad1)));

  EXPECT_THAT(kmsAead->get()->Encrypt(kPlaintext, kAad2),
              IsOkAndHolds(*aead.Encrypt(kPlaintext, kAad2)));

  // Different AADs generate different ciphertexts.
  EXPECT_NE(*kmsAead->get()->Encrypt(kPlaintext, kAad1),
            *kmsAead->get()->Encrypt(kPlaintext, kAad2));

  // Decryption works.
  EXPECT_THAT(kmsAead->get()->Decrypt(
                  *kmsAead->get()->Encrypt(kPlaintext, kAad1), kAad1),
              IsOkAndHolds(*aead.Decrypt(
                  *kmsAead->get()->Encrypt(kPlaintext, kAad1), kAad1)));

  EXPECT_THAT(kmsAead->get()->Decrypt(
                  *kmsAead->get()->Encrypt(kPlaintext, kAad2), kAad2),
              IsOkAndHolds(*aead.Decrypt(
                  *kmsAead->get()->Encrypt(kPlaintext, kAad2), kAad2)));

  // Decryption with a different AAD fails.
  EXPECT_THAT(kmsAead->get()
                  ->Decrypt(*kmsAead->get()->Encrypt(kPlaintext, kAad1), kAad2)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("KMS decryption failed")));
}

}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
