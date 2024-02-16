// Copyright 2022 Google LLC
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

#include "tink/internal/key_serializer.h"

#include <memory>
#include <string_view>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_test_util.h"
#include "tink/internal/serializer_index.h"
#include "tink/key.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;

TEST(KeySerializerTest, Create) {
  std::unique_ptr<KeySerializer> serializer =
      absl::make_unique<KeySerializerImpl<NoIdKey, NoIdSerialization>>(
          SerializeNoIdKey);

  EXPECT_THAT(serializer->Index(),
              Eq(SerializerIndex::Create<NoIdKey, NoIdSerialization>()));
}

TEST(KeySerializerTest, SerializeKey) {
  std::unique_ptr<KeySerializer> serializer =
      absl::make_unique<KeySerializerImpl<NoIdKey, NoIdSerialization>>(
          SerializeNoIdKey);

  NoIdKey key;
  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      serializer->SerializeKey(key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kNoIdTypeUrl));
}

TEST(KeySerializerTest, SerializePublicKeyNoAccessToken) {
  std::unique_ptr<KeySerializer> serializer =
      absl::make_unique<KeySerializerImpl<NoIdKey, NoIdSerialization>>(
          SerializeNoIdKey);

  NoIdKey public_key;
  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      serializer->SerializeKey(public_key, absl::nullopt);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kNoIdTypeUrl));
}

TEST(KeySerializerTest, SerializeKeyWithInvalidKeyType) {
  std::unique_ptr<KeySerializer> serializer =
      absl::make_unique<KeySerializerImpl<NoIdKey, NoIdSerialization>>(
          SerializeNoIdKey);

  IdKey key(/*id=*/123);
  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      serializer->SerializeKey(key, InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization.status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
