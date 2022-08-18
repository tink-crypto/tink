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

#include "tink/restricted_data.h"

#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/subtle/random.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {

using ::crypto::tink::subtle::Random;
using ::testing::Eq;
using ::testing::SizeIs;

TEST(RestrictedDataTest, CreateAndGetSecret) {
  const std::string secret = Random::GetRandomBytes(32);
  RestrictedData data(secret, InsecureSecretKeyAccess::Get());

  EXPECT_THAT(data.GetSecret(InsecureSecretKeyAccess::Get()), Eq(secret));
}

TEST(RestrictedDataTest, GenerateRandomAndSize) {
  RestrictedData data(/*num_random_bytes=*/32);

  EXPECT_THAT(data.GetSecret(InsecureSecretKeyAccess::Get()), SizeIs(32));
  EXPECT_THAT(data.size(), Eq(32));
}

TEST(RestrictedDataTest, GenerateRandomNegative) {
  EXPECT_DEATH_IF_SUPPORTED(
      RestrictedData(/*num_random_bytes=*/-1),
      "Cannot generate a negative number of random bytes.\n");
}

TEST(RestrictedDataTest, Equals) {
  const std::string secret = Random::GetRandomBytes(32);
  RestrictedData data(secret, InsecureSecretKeyAccess::Get());
  RestrictedData same_data(secret, InsecureSecretKeyAccess::Get());

  EXPECT_TRUE(data == same_data);
  EXPECT_TRUE(same_data == data);
  EXPECT_FALSE(data != same_data);
  EXPECT_FALSE(same_data != data);
}

TEST(RestrictedDataTest, NotEquals) {
  RestrictedData data(
      util::SecretDataAsStringView(Random::GetRandomKeyBytes(32)),
      InsecureSecretKeyAccess::Get());
  RestrictedData diff_data(
      util::SecretDataAsStringView(Random::GetRandomKeyBytes(32)),
      InsecureSecretKeyAccess::Get());

  EXPECT_TRUE(data != diff_data);
  EXPECT_TRUE(diff_data != data);
  EXPECT_FALSE(data == diff_data);
  EXPECT_FALSE(diff_data == data);
}

TEST(RestrictedDataTest, CopyConstructor) {
  RestrictedData data(/*num_random_bytes=*/32);
  RestrictedData copy(data);

  EXPECT_THAT(copy, SizeIs(32));
  EXPECT_THAT(copy.GetSecret(InsecureSecretKeyAccess::Get()),
              Eq(data.GetSecret(InsecureSecretKeyAccess::Get())));
}

TEST(RestrictedDataTest, CopyAssignment) {
  RestrictedData data(/*num_random_bytes=*/32);
  RestrictedData copy = data;

  EXPECT_THAT(copy, SizeIs(32));
  EXPECT_THAT(copy.GetSecret(InsecureSecretKeyAccess::Get()),
              Eq(copy.GetSecret(InsecureSecretKeyAccess::Get())));
}

TEST(RestrictedDataTest, MoveConstructor) {
  const std::string secret = Random::GetRandomBytes(32);
  RestrictedData data(secret, InsecureSecretKeyAccess::Get());
  RestrictedData move(std::move(data));

  EXPECT_THAT(move, SizeIs(32));
  EXPECT_THAT(move.GetSecret(InsecureSecretKeyAccess::Get()), Eq(secret));
}

TEST(RestrictedDataTest, MoveAssignment) {
  const std::string secret = Random::GetRandomBytes(32);
  RestrictedData data(secret, InsecureSecretKeyAccess::Get());
  RestrictedData move = std::move(data);

  EXPECT_THAT(move, SizeIs(32));
  EXPECT_THAT(move.GetSecret(InsecureSecretKeyAccess::Get()), Eq(secret));
}

}  // namespace tink
}  // namespace crypto
