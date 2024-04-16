// Copyright 2024 Google LLC
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

#include "tink/experimental/pqcrypto/signature/slh_dsa_private_key.h"

#include <cstdint>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#define OPENSSL_UNSTABLE_EXPERIMENTAL_SPX
#include "openssl/experimental/spx.h"
#undef OPENSSL_UNSTABLE_EXPERIMENTAL_SPX
#include "tink/experimental/pqcrypto/signature/slh_dsa_parameters.h"
#include "tink/experimental/pqcrypto/signature/slh_dsa_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/subtle/random.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  SlhDsaParameters::Variant variant;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

using SlhDsaPrivateKeyTest = TestWithParam<TestCase>;

INSTANTIATE_TEST_SUITE_P(
    SlhDsaPrivateKeyTestSuite, SlhDsaPrivateKeyTest,
    Values(TestCase{SlhDsaParameters::Variant::kTink, 0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{SlhDsaParameters::Variant::kTink, 0x03050709,
                    std::string("\x01\x03\x05\x07\x09", 5)},
           TestCase{SlhDsaParameters::Variant::kNoPrefix, absl::nullopt, ""}));

TEST_P(SlhDsaPrivateKeyTest, CreateSucceeds) {
  TestCase test_case = GetParam();

  util::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2,
      /*private_key_size_in_bytes=*/SPX_SECRET_KEY_BYTES,
      SlhDsaParameters::SignatureType::kSmallSignature, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes;
  public_key_bytes.resize(SPX_PUBLIC_KEY_BYTES);
  std::string private_key_bytes;
  private_key_bytes.resize(SPX_SECRET_KEY_BYTES);

  SPX_generate_key(reinterpret_cast<uint8_t *>(public_key_bytes.data()),
                   reinterpret_cast<uint8_t *>(private_key_bytes.data()));

  util::StatusOr<SlhDsaPublicKey> public_key =
      SlhDsaPublicKey::Create(*parameters, public_key_bytes,
                              test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData restricted_private_key_bytes =
      RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get());
  util::StatusOr<SlhDsaPrivateKey> private_key = SlhDsaPrivateKey::Create(
      *public_key, restricted_private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  EXPECT_THAT(private_key->GetParameters(), Eq(*parameters));
  EXPECT_THAT(private_key->GetIdRequirement(), Eq(test_case.id_requirement));
  EXPECT_THAT(private_key->GetPublicKey(), Eq(*public_key));
  EXPECT_THAT(private_key->GetOutputPrefix(), Eq(test_case.output_prefix));
  EXPECT_THAT(private_key->GetPrivateKeyBytes(GetPartialKeyAccess()),
              Eq(restricted_private_key_bytes));
}

TEST(SlhDsaPrivateKeyTest, CreateWithInvalidPrivateKeyLengthFails) {
  util::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2,
      /*private_key_size_in_bytes=*/SPX_SECRET_KEY_BYTES,
      SlhDsaParameters::SignatureType::kSmallSignature,
      SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<SlhDsaPublicKey> public_key = SlhDsaPublicKey::Create(
      *parameters, subtle::Random::GetRandomBytes(SPX_PUBLIC_KEY_BYTES),
      /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData restricted_private_key_bytes = RestrictedData(
      subtle::Random::GetRandomBytes(63), InsecureSecretKeyAccess::Get());
  EXPECT_THAT(
      SlhDsaPrivateKey::Create(*public_key, restricted_private_key_bytes,
                               GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("SLH-DSA private key length must be "
                         "64 bytes")));
}

TEST(SlhDsaPrivateKeyTest, CreateWithMismatchedPairFails) {
  util::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2,
      /*private_key_size_in_bytes=*/SPX_SECRET_KEY_BYTES,
      SlhDsaParameters::SignatureType::kSmallSignature,
      SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes;
  public_key_bytes.resize(SPX_PUBLIC_KEY_BYTES);
  std::string private_key_bytes;
  private_key_bytes.resize(SPX_SECRET_KEY_BYTES);

  SPX_generate_key(reinterpret_cast<uint8_t *>(public_key_bytes.data()),
                   reinterpret_cast<uint8_t *>(private_key_bytes.data()));

  util::StatusOr<SlhDsaPublicKey> public_key =
      SlhDsaPublicKey::Create(*parameters, public_key_bytes,
                              /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  // Generate a new key pair.
  SPX_generate_key(reinterpret_cast<uint8_t *>(public_key_bytes.data()),
                   reinterpret_cast<uint8_t *>(private_key_bytes.data()));
  RestrictedData restricted_private_key_bytes =
      RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get());

  // Creating the private key using the different private_key_bytes should fail.
  EXPECT_THAT(
      SlhDsaPrivateKey::Create(*public_key, restricted_private_key_bytes,
                               GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Invalid SLH-DSA key pair")));
}

TEST(SlhDsaPrivateKeyTest, CreateWithModifiedPrivateKeyFails) {
  util::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2,
      /*private_key_size_in_bytes=*/SPX_SECRET_KEY_BYTES,
      SlhDsaParameters::SignatureType::kSmallSignature,
      SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes;
  public_key_bytes.resize(SPX_PUBLIC_KEY_BYTES);
  std::string private_key_bytes;
  private_key_bytes.resize(SPX_SECRET_KEY_BYTES);

  SPX_generate_key(reinterpret_cast<uint8_t *>(public_key_bytes.data()),
                   reinterpret_cast<uint8_t *>(private_key_bytes.data()));

  util::StatusOr<SlhDsaPublicKey> public_key =
      SlhDsaPublicKey::Create(*parameters, public_key_bytes,
                              /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  // Replace last 16 bytes of the private key bytes with random bytes.
  private_key_bytes.replace(/*seed_size=*/48, /*pk_root_size=*/16,
                            subtle::Random::GetRandomBytes(16));
  RestrictedData restricted_private_key_bytes =
      RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get());

  EXPECT_THAT(
      SlhDsaPrivateKey::Create(*public_key, restricted_private_key_bytes,
                               GetPartialKeyAccess())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Invalid SLH-DSA key pair")));
}

TEST_P(SlhDsaPrivateKeyTest, KeyEquals) {
  TestCase test_case = GetParam();

  util::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2,
      /*private_key_size_in_bytes=*/SPX_SECRET_KEY_BYTES,
      SlhDsaParameters::SignatureType::kSmallSignature, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes;
  public_key_bytes.resize(SPX_PUBLIC_KEY_BYTES);
  std::string private_key_bytes;
  private_key_bytes.resize(SPX_SECRET_KEY_BYTES);

  SPX_generate_key(reinterpret_cast<uint8_t *>(public_key_bytes.data()),
                   reinterpret_cast<uint8_t *>(private_key_bytes.data()));

  util::StatusOr<SlhDsaPublicKey> public_key =
      SlhDsaPublicKey::Create(*parameters, public_key_bytes,
                              test_case.id_requirement, GetPartialKeyAccess());
  ASSERT_THAT(public_key, IsOk());

  RestrictedData restricted_private_key_bytes =
      RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get());
  util::StatusOr<SlhDsaPrivateKey> private_key = SlhDsaPrivateKey::Create(
      *public_key, restricted_private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<SlhDsaPrivateKey> other_private_key = SlhDsaPrivateKey::Create(
      *public_key, restricted_private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(*private_key == *other_private_key);
  EXPECT_TRUE(*other_private_key == *private_key);
  EXPECT_FALSE(*private_key != *other_private_key);
  EXPECT_FALSE(*other_private_key != *private_key);
}

TEST(SlhDsaPrivateKeyTest, DifferentPublicKeyNotEqual) {
  util::StatusOr<SlhDsaParameters> parameters = SlhDsaParameters::Create(
      SlhDsaParameters::HashType::kSha2,
      /*private_key_size_in_bytes=*/SPX_SECRET_KEY_BYTES,
      SlhDsaParameters::SignatureType::kSmallSignature,
      SlhDsaParameters::Variant::kTink);
  ASSERT_THAT(parameters, IsOk());

  std::string public_key_bytes;
  public_key_bytes.resize(SPX_PUBLIC_KEY_BYTES);
  std::string private_key_bytes;
  private_key_bytes.resize(parameters->GetPrivateKeySizeInBytes());

  SPX_generate_key(reinterpret_cast<uint8_t *>(public_key_bytes.data()),
                   reinterpret_cast<uint8_t *>(private_key_bytes.data()));

  util::StatusOr<SlhDsaPublicKey> public_key123 =
      SlhDsaPublicKey::Create(*parameters, public_key_bytes,
                              /*id_requirement=*/123, GetPartialKeyAccess());
  ASSERT_THAT(public_key123, IsOk());

  util::StatusOr<SlhDsaPublicKey> public_key456 =
      SlhDsaPublicKey::Create(*parameters, public_key_bytes,
                              /*id_requirement=*/456, GetPartialKeyAccess());
  ASSERT_THAT(public_key456, IsOk());

  RestrictedData restricted_private_key_bytes =
      RestrictedData(private_key_bytes, InsecureSecretKeyAccess::Get());

  util::StatusOr<SlhDsaPrivateKey> private_key = SlhDsaPrivateKey::Create(
      *public_key123, restricted_private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(private_key, IsOk());

  util::StatusOr<SlhDsaPrivateKey> other_private_key = SlhDsaPrivateKey::Create(
      *public_key456, restricted_private_key_bytes, GetPartialKeyAccess());
  ASSERT_THAT(other_private_key, IsOk());

  EXPECT_TRUE(*private_key != *other_private_key);
  EXPECT_TRUE(*other_private_key != *private_key);
  EXPECT_FALSE(*private_key == *other_private_key);
  EXPECT_FALSE(*other_private_key == *private_key);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
