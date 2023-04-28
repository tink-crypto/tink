// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "tink/integration/gcpkms/gcp_kms_aead.h"
#include "tink/integration/gcpkms/gcp_kms_client.h"
#include "tink/util/test_matchers.h"
#include "tools/cpp/runfiles/runfiles.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace {

using ::bazel::tools::cpp::runfiles::Runfiles;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::testing::Environment;

constexpr absl::string_view kGcpKmsKeyUri =
    "gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/"
    "unit-and-integration-testing/cryptoKeys/aead-key";

std::string RunfilesPath(absl::string_view path) {
  std::string error;
  std::unique_ptr<Runfiles> runfiles(Runfiles::CreateForTest(&error));
  CHECK(runfiles != nullptr) << "Unable to determine runfile path: ";
  const char* workspace_dir = getenv("TEST_WORKSPACE");
  CHECK(workspace_dir != nullptr && workspace_dir[0] != '\0')
      << "Unable to determine workspace name.";
  return runfiles->Rlocation(absl::StrCat(workspace_dir, "/", path));
}

class GcpKmsAeadIntegrationTestEnvironment : public Environment {
 public:
  ~GcpKmsAeadIntegrationTestEnvironment() override = default;

  void SetUp() override {
    // Set root certificates for gRPC in Bazel Test which are needed on macOS.
    const char* test_srcdir = getenv("TEST_SRCDIR");
    if (test_srcdir != nullptr) {
      setenv(
          "GRPC_DEFAULT_SSL_ROOTS_FILE_PATH",
          absl::StrCat(test_srcdir, "/google_root_pem/file/downloaded").c_str(),
          /*overwrite=*/false);
    }
  }
};

Environment* const foo_env = testing::AddGlobalTestEnvironment(
    new GcpKmsAeadIntegrationTestEnvironment());

TEST(GcpKmsAeadIntegrationTest, EncryptDecrypt) {
  std::string credentials = RunfilesPath("testdata/gcp/credential.json");
  util::StatusOr<std::unique_ptr<GcpKmsClient>> client =
      GcpKmsClient::New(/*key_uri=*/"", credentials);
  ASSERT_THAT(client, IsOk());

  util::StatusOr<std::unique_ptr<Aead>> aead =
      (*client)->GetAead(kGcpKmsKeyUri);
  ASSERT_THAT(aead, IsOk());

  constexpr absl::string_view kPlaintext = "plaintext";
  constexpr absl::string_view kAssociatedData = "aad";

  util::StatusOr<std::string> ciphertext =
      (*aead)->Encrypt(kPlaintext, kAssociatedData);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*aead)->Decrypt(*ciphertext, kAssociatedData),
              IsOkAndHolds(kPlaintext));
}

}  // namespace
}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
