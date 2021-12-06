// Copyright 2021 Google LLC
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
#include "tink/internal/ec_util.h"

#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/types/span.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::testing::ElementsAreArray;
using ::testing::Not;

TEST(EcUtilTest, NewX25519KeyGeneratesNewKeyEveryTime) {
  std::unique_ptr<X25519Key> keypair1 = NewX25519Key();
  std::unique_ptr<X25519Key> keypair2 = NewX25519Key();

  auto priv_key1 =
      absl::MakeSpan(keypair1->private_key, X25519KeyPrivKeySize());
  auto priv_key2 =
      absl::MakeSpan(keypair2->private_key, X25519KeyPrivKeySize());
  auto pub_key1 =
      absl::MakeSpan(keypair1->public_value, X25519KeyPubKeySize());
  auto pub_key2 =
      absl::MakeSpan(keypair2->public_value, X25519KeyPubKeySize());
  EXPECT_THAT(priv_key1, Not(ElementsAreArray(priv_key2)));
  EXPECT_THAT(pub_key1, Not(ElementsAreArray(pub_key2)));
}

TEST(EcUtilTest, X25519KeyToEcKeyAndBack) {
  util::StatusOr<std::unique_ptr<X25519Key>> x25519_key = NewX25519Key();
  ASSERT_THAT(x25519_key.status(), IsOk());
  EcKey ec_key = EcKeyFromX25519Key(x25519_key->get());
  ASSERT_EQ(ec_key.curve, subtle::EllipticCurveType::CURVE25519);

  util::StatusOr<std::unique_ptr<X25519Key>> roundtrip_key =
      X25519KeyFromEcKey(ec_key);
  ASSERT_THAT(roundtrip_key.status(), IsOk());
  EXPECT_THAT(
      absl::MakeSpan((*x25519_key)->private_key, X25519KeyPrivKeySize()),
      ElementsAreArray(absl::MakeSpan((*roundtrip_key)->private_key,
                                      X25519KeyPrivKeySize())));
  EXPECT_THAT(
      absl::MakeSpan((*x25519_key)->public_value, X25519KeyPubKeySize()),
      ElementsAreArray(absl::MakeSpan((*roundtrip_key)->public_value,
                                      X25519KeyPubKeySize())));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
