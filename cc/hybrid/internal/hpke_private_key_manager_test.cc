// Copyright 2021 Google LLC
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

#include "tink/hybrid/internal/hpke_private_key_manager.h"

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/hybrid/internal/hpke_encrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/subtle/hybrid_test_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/hpke.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::HpkeAead;
using ::google::crypto::tink::HpkeKdf;
using ::google::crypto::tink::HpkeKem;
using ::google::crypto::tink::HpkeKeyFormat;
using ::google::crypto::tink::HpkeParams;
using ::google::crypto::tink::HpkePrivateKey;
using ::google::crypto::tink::HpkePublicKey;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::Not;

HpkeKeyFormat CreateKeyFormat(HpkeKem kem, HpkeKdf kdf, HpkeAead aead) {
  HpkeKeyFormat key_format;
  HpkeParams *params = key_format.mutable_params();
  params->set_kem(kem);
  params->set_kdf(kdf);
  params->set_aead(aead);
  return key_format;
}

util::StatusOr<HpkePrivateKey> CreateKey(HpkeKem kem, HpkeKdf kdf,
                                         HpkeAead aead) {
  return HpkePrivateKeyManager().CreateKey(CreateKeyFormat(kem, kdf, aead));
}

TEST(HpkePrivateKeyManagerTest, BasicAccessors) {
  EXPECT_THAT(HpkePrivateKeyManager().get_version(), Eq(0));
  EXPECT_THAT(HpkePrivateKeyManager().key_material_type(),
              Eq(KeyData::ASYMMETRIC_PRIVATE));
  EXPECT_THAT(HpkePrivateKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.HpkePrivateKey"));
}

TEST(HpkePrivateKeyManagerTest, ValidateEmptyKeyFormatFails) {
  EXPECT_THAT(HpkePrivateKeyManager().ValidateKeyFormat(HpkeKeyFormat()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyManagerTest, ValidateKeyFormatSucceeds) {
  EXPECT_THAT(HpkePrivateKeyManager().ValidateKeyFormat(
                  CreateKeyFormat(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                                  HpkeKdf::HKDF_SHA256, HpkeAead::AES_128_GCM)),
              IsOk());
}

TEST(HpkePrivateKeyManagerTest, ValidateKeyFormatWithInvalidKemFails) {
  EXPECT_THAT(
      HpkePrivateKeyManager().ValidateKeyFormat(CreateKeyFormat(
          HpkeKem::KEM_UNKNOWN, HpkeKdf::HKDF_SHA256, HpkeAead::AES_128_GCM)),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyManagerTest, ValidateKeyFormatWithInvalidKdfFails) {
  EXPECT_THAT(HpkePrivateKeyManager().ValidateKeyFormat(
                  CreateKeyFormat(HpkeKem::DHKEM_X25519_HKDF_SHA256,
                                  HpkeKdf::KDF_UNKNOWN, HpkeAead::AES_128_GCM)),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyManagerTest, ValidateKeyFormatWithInvalidAeadFails) {
  EXPECT_THAT(HpkePrivateKeyManager().ValidateKeyFormat(CreateKeyFormat(
                  HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                  HpkeAead::AEAD_UNKNOWN)),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyManagerTest, CreateKeySucceeds) {
  HpkeKeyFormat key_format =
      CreateKeyFormat(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                      HpkeAead::AES_128_GCM);

  util::StatusOr<HpkePrivateKey> key =
      HpkePrivateKeyManager().CreateKey(key_format);
  ASSERT_THAT(key, IsOk());

  ASSERT_TRUE(key->has_public_key());
  ASSERT_TRUE(key->public_key().has_params());
  EXPECT_THAT(key->public_key().params().kem(), Eq(key_format.params().kem()));
  EXPECT_THAT(key->public_key().params().kdf(), Eq(key_format.params().kdf()));
  EXPECT_THAT(key->public_key().params().aead(),
              Eq(key_format.params().aead()));
  EXPECT_THAT(key->public_key().public_key(), Not(IsEmpty()));
  EXPECT_THAT(key->private_key(), Not(IsEmpty()));
}

TEST(HpkePrivateKeyManagerTest, CreateKeyWithInvalidKemFails) {
  HpkeKeyFormat key_format = CreateKeyFormat(
      HpkeKem::KEM_UNKNOWN, HpkeKdf::HKDF_SHA256, HpkeAead::AES_128_GCM);

  ASSERT_THAT(HpkePrivateKeyManager().CreateKey(key_format).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyManagerTest, ValidateEmptyKeyFails) {
  EXPECT_THAT(HpkePrivateKeyManager().ValidateKey(HpkePrivateKey()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyManagerTest, ValidateKeySucceeds) {
  util::StatusOr<HpkePrivateKey> key =
      CreateKey(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                HpkeAead::AES_128_GCM);
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(HpkePrivateKeyManager().ValidateKey(*key), IsOk());
}

TEST(HpkePrivateKeyManagerTest, ValidateKeyWithWrongVersionFails) {
  util::StatusOr<HpkePrivateKey> key =
      CreateKey(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                HpkeAead::AES_128_GCM);
  ASSERT_THAT(key, IsOk());
  key->set_version(1);

  EXPECT_THAT(HpkePrivateKeyManager().ValidateKey(*key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyManagerTest, ValidateKeyWithInvalidKemFails) {
  util::StatusOr<HpkePrivateKey> key =
      CreateKey(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                HpkeAead::AES_128_GCM);
  ASSERT_THAT(key, IsOk());
  key->mutable_public_key()->mutable_params()->set_kem(HpkeKem::KEM_UNKNOWN);

  EXPECT_THAT(HpkePrivateKeyManager().ValidateKey(*key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyManagerTest, ValidateKeyWithInvalidKdfFails) {
  util::StatusOr<HpkePrivateKey> key =
      CreateKey(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::KDF_UNKNOWN,
                HpkeAead::AES_128_GCM);
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(HpkePrivateKeyManager().ValidateKey(*key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyManagerTest, ValidateKeyWithInvalidAeadFails) {
  util::StatusOr<HpkePrivateKey> key =
      CreateKey(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                HpkeAead::AEAD_UNKNOWN);
  ASSERT_THAT(key, IsOk());

  EXPECT_THAT(HpkePrivateKeyManager().ValidateKey(*key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(HpkePrivateKeyManagerTest, GetPublicKeySucceeds) {
  HpkeKeyFormat key_format =
      CreateKeyFormat(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                      HpkeAead::AES_128_GCM);
  util::StatusOr<HpkePrivateKey> key =
      HpkePrivateKeyManager().CreateKey(key_format);
  ASSERT_THAT(key, IsOk());

  util::StatusOr<HpkePublicKey> public_key =
      HpkePrivateKeyManager().GetPublicKey(*key);
  ASSERT_THAT(public_key, IsOk());

  ASSERT_TRUE(key->has_public_key());
  ASSERT_TRUE(key->public_key().has_params());
  EXPECT_THAT(public_key->params().kem(), Eq(key_format.params().kem()));
  EXPECT_THAT(public_key->params().kdf(), Eq(key_format.params().kdf()));
  EXPECT_THAT(public_key->params().aead(), Eq(key_format.params().aead()));
  ASSERT_THAT(public_key->public_key(), Not(IsEmpty()));
  EXPECT_THAT(public_key->public_key(), Eq(key->public_key().public_key()));
}

TEST(HpkePrivateKeyManagerTest, EncryptThenDecryptSucceeds) {
  util::StatusOr<HpkePrivateKey> private_key =
      CreateKey(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                HpkeAead::AES_128_GCM);
  ASSERT_THAT(private_key, IsOk());
  util::StatusOr<HpkePublicKey> public_key =
      HpkePrivateKeyManager().GetPublicKey(*private_key);
  ASSERT_THAT(public_key, IsOk());
  util::StatusOr<std::unique_ptr<HybridDecrypt>> decrypt =
      HpkePrivateKeyManager().GetPrimitive<HybridDecrypt>(*private_key);
  ASSERT_THAT(decrypt, IsOk());
  util::StatusOr<std::unique_ptr<HybridEncrypt>> encrypt =
      HpkeEncrypt::New(*public_key);
  ASSERT_THAT(encrypt, IsOk());

  ASSERT_THAT(HybridEncryptThenDecrypt(encrypt->get(), decrypt->get(),
                                       "some text", "some aad"),
              IsOk());
}

TEST(HpkePrivateKeyManagerTest, EncryptThenDecryptWithDifferentKeysFails) {
  util::StatusOr<HpkePrivateKey> private_key =
      CreateKey(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                HpkeAead::AES_128_GCM);
  ASSERT_THAT(private_key, IsOk());
  util::StatusOr<HpkePrivateKey> different_private_key =
      CreateKey(HpkeKem::DHKEM_X25519_HKDF_SHA256, HpkeKdf::HKDF_SHA256,
                HpkeAead::AES_128_GCM);
  ASSERT_THAT(different_private_key, IsOk());
  util::StatusOr<HpkePublicKey> public_key =
      HpkePrivateKeyManager().GetPublicKey(*different_private_key);
  ASSERT_THAT(public_key, IsOk());
  util::StatusOr<std::unique_ptr<HybridDecrypt>> decrypt =
      HpkePrivateKeyManager().GetPrimitive<HybridDecrypt>(*private_key);
  ASSERT_THAT(decrypt, IsOk());
  util::StatusOr<std::unique_ptr<HybridEncrypt>> encrypt =
      HpkeEncrypt::New(*public_key);
  ASSERT_THAT(encrypt, IsOk());

  ASSERT_THAT(HybridEncryptThenDecrypt(encrypt->get(), decrypt->get(),
                                       "some text", "some aad"),
              Not(IsOk()));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
