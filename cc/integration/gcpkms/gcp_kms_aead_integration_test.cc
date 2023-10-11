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

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>

#include "google/cloud/kms/v1/service.grpc.pb.h"
#include "grpcpp/channel.h"
#include "grpcpp/create_channel.h"
#include "grpcpp/security/credentials.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/integration/gcpkms/gcp_kms_aead.h"
#include "tink/integration/gcpkms/gcp_kms_client.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
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
using ::google::cloud::kms::v1::KeyManagementService;
using ::testing::Environment;
using ::testing::Not;

constexpr absl::string_view kGcpKmsKeyUri =
    "gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/"
    "unit-and-integration-testing/cryptoKeys/aead-key";

constexpr absl::string_view kGcpKmsKeyName =
    "projects/tink-test-infrastructure/locations/global/keyRings/"
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
  constexpr absl::string_view kAssociatedData = "associatedData";

  util::StatusOr<std::string> ciphertext =
      (*aead)->Encrypt(kPlaintext, kAssociatedData);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*aead)->Decrypt(*ciphertext, kAssociatedData),
              IsOkAndHolds(kPlaintext));

  EXPECT_THAT((*aead)->Decrypt(*ciphertext, "invalidAssociatedData"),
              Not(IsOk()));
}

util::StatusOr<std::string> ReadFile(const std::string& filename) {
  std::ifstream input_stream;
  input_stream.open(filename, std::ifstream::in);
  if (!input_stream.is_open()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("Error opening file ", filename));
  }
  std::stringstream input;
  input << input_stream.rdbuf();
  input_stream.close();
  return input.str();
}

TEST(GcpKmsAeadIntegrationTest, GcpKmsAeadNewWorks) {
  // Read credentials file.
  std::string credentials_path = RunfilesPath("testdata/gcp/credential.json");
  util::StatusOr<std::string> json_creds = ReadFile(credentials_path);
  ASSERT_THAT(json_creds, IsOk());

  // Create a GCP KMS stub.
  std::shared_ptr<grpc::CallCredentials> creds =
      grpc::ServiceAccountJWTAccessCredentials(*json_creds);
  std::shared_ptr<grpc::ChannelCredentials> channel_creds =
      grpc::SslCredentials(grpc::SslCredentialsOptions());
  std::shared_ptr<grpc::ChannelCredentials> credentials =
      grpc::CompositeChannelCredentials(channel_creds, creds);
  grpc::ChannelArguments args;
  args.SetUserAgentPrefix("Tink Test CPP");
  std::shared_ptr<KeyManagementService::Stub> kms_stub =
      KeyManagementService::NewStub(grpc::CreateCustomChannel(
          "cloudkms.googleapis.com", credentials, args));

  util::StatusOr<std::unique_ptr<Aead>> aead =
      GcpKmsAead::New(kGcpKmsKeyName, kms_stub);
  ASSERT_THAT(aead, IsOk());

  constexpr absl::string_view kPlaintext = "plaintext";
  constexpr absl::string_view kAssociatedData = "associatedData";

  util::StatusOr<std::string> ciphertext =
      (*aead)->Encrypt(kPlaintext, kAssociatedData);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*aead)->Decrypt(*ciphertext, kAssociatedData),
              IsOkAndHolds(kPlaintext));

  EXPECT_THAT((*aead)->Decrypt(*ciphertext, "invalidAssociatedData"),
              Not(IsOk()));
}

}  // namespace
}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
