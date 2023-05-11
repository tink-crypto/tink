// Copyright 2019 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

#include "tink/keyderivation/internal/prf_based_deriver_key_manager.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/keyderivation/keyset_deriver.h"
#include "tink/prf/hkdf_prf_key_manager.h"
#include "tink/subtle/random.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/aes_gcm.pb.h"
#include "proto/hkdf_prf.pb.h"
#include "proto/prf_based_deriver.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::AesGcmKey;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::HkdfPrfKey;
using ::google::crypto::tink::HkdfPrfKeyFormat;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::PrfBasedDeriverKey;
using ::google::crypto::tink::PrfBasedDeriverKeyFormat;
using ::testing::Eq;
using ::testing::SizeIs;

TEST(PrfBasedDeriverKeyManagerTest, Basics) {
  EXPECT_THAT(PrfBasedDeriverKeyManager().get_version(), Eq(0));
  EXPECT_THAT(PrfBasedDeriverKeyManager().get_key_type(),
              Eq("type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey"));
  EXPECT_THAT(PrfBasedDeriverKeyManager().key_material_type(),
              Eq(KeyData::SYMMETRIC));
}

TEST(PrfBasedDeriverKeyManagerTest, ValidateKeyEmpty) {
  EXPECT_THAT(PrfBasedDeriverKeyManager().ValidateKey(PrfBasedDeriverKey()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PrfBasedDeriverKeyManagerTest, ValidateKey) {
  HkdfPrfKey prf_key;
  prf_key.set_version(0);
  prf_key.set_key_value("0123456789abcdef");
  prf_key.mutable_params()->set_hash(HashType::SHA256);

  PrfBasedDeriverKey key;
  key.set_version(0);
  *key.mutable_prf_key() = test::AsKeyData(prf_key, KeyData::SYMMETRIC);
  *key.mutable_params()->mutable_derived_key_template() =
      AeadKeyTemplates::Aes256Gcm();

  EXPECT_THAT(PrfBasedDeriverKeyManager().ValidateKey(key), IsOk());
}

TEST(PrfBasedDeriverKeyManagerTest, ValidateKeyWithWrongVersion) {
  HkdfPrfKey prf_key;
  prf_key.set_version(0);
  prf_key.set_key_value("0123456789abcdef");
  prf_key.mutable_params()->set_hash(HashType::SHA256);

  PrfBasedDeriverKey key;
  key.set_version(1);
  *key.mutable_prf_key() = test::AsKeyData(prf_key, KeyData::SYMMETRIC);
  *key.mutable_params()->mutable_derived_key_template() =
      AeadKeyTemplates::Aes256Gcm();

  EXPECT_THAT(PrfBasedDeriverKeyManager().ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PrfBasedDeriverKeyManagerTest, ValidateKeyFormat) {
  HkdfPrfKeyFormat prf_key_format;
  prf_key_format.set_key_size(16);
  prf_key_format.mutable_params()->set_hash(HashType::SHA256);

  PrfBasedDeriverKeyFormat key_format;
  key_format.mutable_prf_key_template()->set_type_url(
      HkdfPrfKeyManager().get_key_type());
  key_format.mutable_prf_key_template()->set_value(
      prf_key_format.SerializeAsString());
  *key_format.mutable_params()->mutable_derived_key_template() =
      AeadKeyTemplates::Aes256Gcm();

  EXPECT_THAT(PrfBasedDeriverKeyManager().ValidateKeyFormat(key_format),
              IsOk());
}

TEST(PrfBasedDeriverKeyManagerTest, ValidateKeyFormatEmpty) {
  EXPECT_THAT(
      PrfBasedDeriverKeyManager().ValidateKeyFormat(PrfBasedDeriverKeyFormat()),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PrfBasedDeriverKeyManagerTest, CreateKey) {
  Registry::Reset();
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<HkdfPrfKeyManager>(), true),
              IsOk());
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<HkdfPrfKeyManager>(), true),
              IsOk());
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), true),
              IsOk());

  HkdfPrfKeyFormat prf_key_format;
  prf_key_format.set_key_size(32);
  prf_key_format.mutable_params()->set_hash(HashType::SHA256);

  PrfBasedDeriverKeyFormat key_format;
  key_format.mutable_prf_key_template()->set_type_url(
      HkdfPrfKeyManager().get_key_type());
  key_format.mutable_prf_key_template()->set_value(
      prf_key_format.SerializeAsString());
  *key_format.mutable_params()->mutable_derived_key_template() =
      AeadKeyTemplates::Aes256Gcm();

  util::StatusOr<PrfBasedDeriverKey> key =
      PrfBasedDeriverKeyManager().CreateKey(key_format);
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT((*key).version(), Eq(0));
  EXPECT_THAT((*key).prf_key().type_url(),
              Eq(HkdfPrfKeyManager().get_key_type()));
  EXPECT_THAT((*key).prf_key().key_material_type(), Eq(KeyData::SYMMETRIC));

  HkdfPrfKey prf_key;
  ASSERT_TRUE(prf_key.ParseFromString((*key).prf_key().value()));
  EXPECT_THAT(prf_key.key_value().size(), Eq(32));

  EXPECT_THAT((*key).params().derived_key_template().type_url(),
              Eq(key_format.params().derived_key_template().type_url()));
  EXPECT_THAT((*key).params().derived_key_template().value(),
              Eq(key_format.params().derived_key_template().value()));
}

TEST(PrfBasedDeriverKeyManagerTest, CreateKeyWithInvalidPrfKey) {
  Registry::Reset();
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<HkdfPrfKeyManager>(), true),
              IsOk());
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<HkdfPrfKeyManager>(), true),
              IsOk());
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), true),
              IsOk());

  HkdfPrfKeyFormat prf_key_format;
  prf_key_format.set_key_size(32);
  prf_key_format.mutable_params()->set_hash(HashType::UNKNOWN_HASH);

  PrfBasedDeriverKeyFormat key_format;
  key_format.mutable_prf_key_template()->set_type_url(
      HkdfPrfKeyManager().get_key_type());
  key_format.mutable_prf_key_template()->set_value(
      prf_key_format.SerializeAsString());
  *key_format.mutable_params()->mutable_derived_key_template() =
      AeadKeyTemplates::Aes256Gcm();

  EXPECT_THAT(PrfBasedDeriverKeyManager().CreateKey(key_format).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PrfBasedDeriverKeyManagerTest, CreateKeyWithInvalidDerivedKeyTemplate) {
  Registry::Reset();
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<HkdfPrfKeyManager>(), true),
              IsOk());
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<HkdfPrfKeyManager>(), true),
              IsOk());
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), true),
              IsOk());

  HkdfPrfKeyFormat prf_key_format;
  prf_key_format.set_key_size(32);
  prf_key_format.mutable_params()->set_hash(HashType::SHA256);
  KeyTemplate derived_template;
  derived_template.set_type_url("nonexistent.type.url");

  PrfBasedDeriverKeyFormat key_format;
  key_format.mutable_prf_key_template()->set_type_url(
      HkdfPrfKeyManager().get_key_type());
  key_format.mutable_prf_key_template()->set_value(
      prf_key_format.SerializeAsString());
  *key_format.mutable_params()->mutable_derived_key_template() =
      derived_template;

  // See comment in PrfBasedDeriverKeyManager::CreateKey().
  EXPECT_THAT(PrfBasedDeriverKeyManager().CreateKey(key_format).status(),
              IsOk());
}

TEST(PrfBasedDeriverKeyManagerTest, GetPrimitive) {
  Registry::Reset();
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<PrfBasedDeriverKeyManager>(), true),
              IsOk());
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<HkdfPrfKeyManager>(), true),
              IsOk());
  ASSERT_THAT(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), true),
              IsOk());

  HkdfPrfKey prf_key;
  prf_key.set_version(0);
  prf_key.mutable_params()->set_hash(HashType::SHA256);
  prf_key.mutable_params()->set_salt(subtle::Random::GetRandomBytes(15));
  prf_key.set_key_value(subtle::Random::GetRandomBytes(33));
  prf_key.mutable_params()->set_hash(HashType::SHA256);
  PrfBasedDeriverKey key;
  key.set_version(0);
  *key.mutable_prf_key() = test::AsKeyData(prf_key, KeyData::SYMMETRIC);
  *key.mutable_params()->mutable_derived_key_template() =
      AeadKeyTemplates::Aes256Gcm();

  StatusOr<std::unique_ptr<KeysetDeriver>> deriver =
      PrfBasedDeriverKeyManager().GetPrimitive<KeysetDeriver>(key);
  ASSERT_THAT(deriver, IsOk());

  std::string salt = subtle::Random::GetRandomBytes(23);
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      (*deriver)->DeriveKeyset(salt);
  ASSERT_THAT(handle, IsOk());
  Keyset keyset = CleartextKeysetHandle::GetKeyset(**handle);

  StatusOr<std::unique_ptr<KeysetDeriver>> direct_deriver =
      internal::PrfBasedDeriver::New(key.prf_key(),
                                     key.params().derived_key_template());
  ASSERT_THAT(direct_deriver, IsOk());
  util::StatusOr<std::unique_ptr<KeysetHandle>> direct_handle =
      (*direct_deriver)->DeriveKeyset(salt);
  ASSERT_THAT(direct_handle, IsOk());
  Keyset direct_keyset = CleartextKeysetHandle::GetKeyset(**direct_handle);

  ASSERT_THAT(keyset.key(), SizeIs(1));
  ASSERT_THAT(direct_keyset.key(), SizeIs(1));

  ASSERT_THAT(keyset.key(0).key_data().type_url(),
              Eq(keyset.key(0).key_data().type_url()));

  AesGcmKey derived_key;
  ASSERT_TRUE(derived_key.ParseFromString(keyset.key(0).key_data().value()));
  AesGcmKey direct_derived_key;
  ASSERT_TRUE(direct_derived_key.ParseFromString(
      direct_keyset.key(0).key_data().value()));
  EXPECT_THAT(derived_key.key_value(), Eq(direct_derived_key.key_value()));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
