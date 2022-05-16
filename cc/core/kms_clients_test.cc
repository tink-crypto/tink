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

#include "tink/kms_clients.h"

#include <memory>
#include <string>

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/kms_client.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using crypto::tink::test::IsOk;
using crypto::tink::test::StatusIs;
using crypto::tink::test::DummyKmsClient;

TEST(KmsClientsTest, Empty) {
  auto client_result = KmsClients::Get("some uri");
  EXPECT_THAT(client_result.status(), StatusIs(absl::StatusCode::kNotFound));

  client_result = KmsClients::Get("");
  EXPECT_THAT(client_result.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  auto status = KmsClients::Add(nullptr);
  EXPECT_THAT(status, StatusIs(absl::StatusCode::kInvalidArgument));
}

struct UriData {
  std::string prefix;
  std::string uri;
};

TEST(KmsClientsTest, AddAndGet) {
  UriData data_1 = {"prefix1", "prefix1:uri1"};
  UriData data_2 = {"prefix1", "prefix1:uri2"};
  UriData data_3 = {"prefix2", "prefix2:uri42"};

  // Add client for data_1, and verify it.
  auto status = KmsClients::Add(
      absl::make_unique<DummyKmsClient>(data_1.prefix, data_1.uri));
  EXPECT_THAT(status, IsOk());
  auto client_result = KmsClients::Get(data_1.uri);
  EXPECT_THAT(client_result.status(), IsOk());
  EXPECT_TRUE(client_result.value()->DoesSupport(data_1.uri));
  EXPECT_FALSE(client_result.value()->DoesSupport(data_2.uri));

  // Verify there is no client for data_2.
  client_result = KmsClients::Get(data_2.uri);
  EXPECT_THAT(client_result.status(), StatusIs(absl::StatusCode::kNotFound));

  // Add client for data_2, and verify it.
  status = KmsClients::Add(
      absl::make_unique<DummyKmsClient>(data_2.prefix, data_2.uri));
  EXPECT_THAT(status, IsOk());
  client_result = KmsClients::Get(data_2.uri);
  EXPECT_THAT(client_result.status(), IsOk());
  EXPECT_TRUE(client_result.value()->DoesSupport(data_2.uri));
  EXPECT_FALSE(client_result.value()->DoesSupport(data_1.uri));

  // Verify there is no client for data_3.
  client_result = KmsClients::Get(data_3.uri);
  EXPECT_THAT(client_result.status(), StatusIs(absl::StatusCode::kNotFound));

  // Add client for data_3, and verify it.
  status = KmsClients::Add(
      absl::make_unique<DummyKmsClient>(data_3.prefix, data_3.uri));
  EXPECT_THAT(status, IsOk());
  client_result = KmsClients::Get(data_3.uri);
  EXPECT_THAT(client_result.status(), IsOk());
  EXPECT_TRUE(client_result.value()->DoesSupport(data_3.uri));
  EXPECT_FALSE(client_result.value()->DoesSupport(data_2.uri));
  EXPECT_FALSE(client_result.value()->DoesSupport(data_1.uri));

  // Verify that clients for data_1 and data_2 are still present.
  client_result = KmsClients::Get(data_1.uri);
  EXPECT_THAT(client_result.status(), IsOk());
  EXPECT_TRUE(client_result.value()->DoesSupport(data_1.uri));
  EXPECT_FALSE(client_result.value()->DoesSupport(data_2.uri));

  client_result = KmsClients::Get(data_2.uri);
  EXPECT_THAT(client_result.status(), IsOk());
  EXPECT_TRUE(client_result.value()->DoesSupport(data_2.uri));
  EXPECT_FALSE(client_result.value()->DoesSupport(data_1.uri));
}


}  // namespace
}  // namespace tink
}  // namespace crypto
