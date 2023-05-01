// Copyright 2019 Google LLC
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

#include "tink/integration/gcpkms/gcp_kms_client.h"

#include <cstdlib>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/kms_clients.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;

TEST(GcpKmsClientTest, ClientNotBoundToAKey) {
  std::string gcp_key1 = "gcp-kms://projects/someProject/.../cryptoKeys/key1";
  std::string gcp_key2 = "gcp-kms://projects/otherProject/.../cryptoKeys/key2";
  std::string non_gcp_key = "aws-kms://arn:aws:kms:us-west-2:acc:other/key3";
  std::string creds_file =
      std::string(getenv("TEST_SRCDIR")) + "/tink_cc_gcpkms/testdata/gcp/credential.json";

  util::StatusOr<std::unique_ptr<GcpKmsClient>> client =
      GcpKmsClient::New("", creds_file);
  ASSERT_THAT(client, IsOk());
  EXPECT_TRUE((*client)->DoesSupport(gcp_key1));
  EXPECT_TRUE((*client)->DoesSupport(gcp_key2));
  EXPECT_FALSE((*client)->DoesSupport(non_gcp_key));
}

TEST(GcpKmsClientTest, ClientBoundToASpecificKey) {
  std::string gcp_key1 = "gcp-kms://projects/someProject/.../cryptoKeys/key1";
  std::string gcp_key2 = "gcp-kms://projects/otherProject/.../cryptoKeys/key2";
  std::string non_gcp_key = "aws-kms://arn:aws:kms:us-west-2:acc:other/key3";
  std::string creds_file =
      std::string(getenv("TEST_SRCDIR")) + "/tink_cc_gcpkms/testdata/gcp/credential.json";

  util::StatusOr<std::unique_ptr<GcpKmsClient>> client =
      GcpKmsClient::New(gcp_key1, creds_file);
  ASSERT_THAT(client, IsOk());
  EXPECT_TRUE((*client)->DoesSupport(gcp_key1));
  EXPECT_FALSE((*client)->DoesSupport(gcp_key2));
  EXPECT_FALSE((*client)->DoesSupport(non_gcp_key));
}

TEST(GcpKmsClientTest, ClientCreationAndRegistry) {
  std::string gcp_key1 = "gcp-kms://projects/someProject/.../cryptoKeys/key1";
  std::string creds_file =
      absl::StrCat(getenv("TEST_SRCDIR"), "/tink_cc_gcpkms/testdata/gcp/credential.json");

  util::Status client_result =
      GcpKmsClient::RegisterNewClient(gcp_key1, creds_file);
  ASSERT_THAT(client_result, IsOk());

  util::StatusOr<const KmsClient*> registry_result = KmsClients::Get(gcp_key1);
  EXPECT_THAT(registry_result, IsOk());
}

TEST(GcpKmsClientTest, ClientCreationInvalidRegistry) {
  std::string non_gcp_key = "aws-kms://arn:aws:kms:us-west-2:acc:other/key3";
  std::string creds_file =
      std::string(getenv("TEST_SRCDIR")) + "/tink_cc_gcpkms/testdata/gcp/credential.json";

  util::Status client_result =
      GcpKmsClient::RegisterNewClient(non_gcp_key, creds_file);
  EXPECT_THAT(client_result, StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
