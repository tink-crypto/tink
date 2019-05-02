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

#include "absl/strings/str_cat.h"
#include "gtest/gtest.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {
namespace {

using crypto::tink::integration::gcpkms::GcpKmsClient;

TEST(GcpKmsClientTest, ClientNotBoundToAKey) {
  std::string gcp_key1 = "gcp-kms://projects/someProject/.../cryptoKeys/key1";
  std::string gcp_key2 = "gcp-kms://projects/otherProject/.../cryptoKeys/key2";
  std::string non_gcp_key = "aws-kms://arn:aws:kms:us-west-2:acc:other/key3";
  std::string creds_file = std::string(getenv("TEST_SRCDIR")) +
                      "/tink/testdata/credential.json";

  auto client_result = GcpKmsClient::New("", creds_file);
  EXPECT_TRUE(client_result.ok()) << client_result.status();
  auto client = std::move(client_result.ValueOrDie());
  EXPECT_TRUE(client->DoesSupport(gcp_key1));
  EXPECT_TRUE(client->DoesSupport(gcp_key2));
  EXPECT_FALSE(client->DoesSupport(non_gcp_key));
}

TEST(GcpKmsClientTest, ClientBoundToASpecificKey) {
  std::string gcp_key1 = "gcp-kms://projects/someProject/.../cryptoKeys/key1";
  std::string gcp_key2 = "gcp-kms://projects/otherProject/.../cryptoKeys/key2";
  std::string non_gcp_key = "aws-kms://arn:aws:kms:us-west-2:acc:other/key3";
  std::string creds_file = std::string(getenv("TEST_SRCDIR")) +
                      "/tink/testdata/credential.json";

  auto client_result = GcpKmsClient::New(gcp_key1, creds_file);
  EXPECT_TRUE(client_result.ok()) << client_result.status();
  auto client = std::move(client_result.ValueOrDie());
  EXPECT_TRUE(client->DoesSupport(gcp_key1));
  EXPECT_FALSE(client->DoesSupport(gcp_key2));
  EXPECT_FALSE(client->DoesSupport(non_gcp_key));
}


}  // namespace
}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
