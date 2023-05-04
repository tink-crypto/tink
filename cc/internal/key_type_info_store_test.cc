// Copyright 2023 Google LLC
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

#include "tink/internal/key_type_info_store.h"

#include <memory>
#include <string>
#include <typeindex>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/aead.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/cord_aead.h"
#include "tink/aead/kms_envelope_aead_key_manager.h"
#include "tink/core/key_manager_impl.h"
#include "tink/internal/fips_utils.h"
#include "tink/key_manager.h"
#include "tink/signature/ecdsa_sign_key_manager.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_gcm.pb.h"
#include "proto/common.pb.h"
#include "proto/ecdsa.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesGcmKeyFormat;
using ::google::crypto::tink::EcdsaKeyFormat;
using ::google::crypto::tink::EcdsaParams;
using ::google::crypto::tink::EcdsaSignatureEncoding;
using ::google::crypto::tink::EllipticCurveType;
using ::google::crypto::tink::HashType;

// TODO(b/265705174): Use fake key managers to avoid relying on key manager
// implementations.
TEST(KeyTypeInfoStoreTest, AddKeyTypeManager) {
  KeyTypeInfoStore store;
  ASSERT_THAT(store.AddKeyTypeManager(absl::make_unique<AesGcmKeyManager>(),
                                      /*new_key_allowed=*/true),
              IsOk());

  std::string type_url = AesGcmKeyManager().get_key_type();
  util::StatusOr<KeyTypeInfoStore::Info*> info = store.Get(type_url);
  ASSERT_THAT(info, IsOk());
  EXPECT_EQ((*info)->new_key_allowed(), true);

  util::StatusOr<const KeyManager<Aead>*> manager =
      (*info)->get_key_manager<Aead>(type_url);
  ASSERT_THAT(manager, IsOk());
  EXPECT_EQ((*manager)->get_key_type(), type_url);
}

TEST(KeyTypeInfoStoreTest, AddKeyTypeManagerNoBoringCrypto) {
  if (!kUseOnlyFips || IsFipsEnabledInSsl()) {
    GTEST_SKIP()
        << "Only supported in FIPS-mode with BoringCrypto not available.";
  }
  KeyTypeInfoStore store;
  EXPECT_THAT(
      store.AddKeyTypeManager(absl::make_unique<KmsEnvelopeAeadKeyManager>(),
                              /*new_key_allowed=*/true),
      StatusIs(absl::StatusCode::kInternal));
}

TEST(KeyTypeInfoStoreTest, AddKeyTypeManagerAndChangeNewKeyAllowed) {
  KeyTypeInfoStore store;
  ASSERT_THAT(store.AddKeyTypeManager(absl::make_unique<AesGcmKeyManager>(),
                                      /*new_key_allowed=*/true),
              IsOk());

  std::string type_url = AesGcmKeyManager().get_key_type();
  util::StatusOr<KeyTypeInfoStore::Info*> info = store.Get(type_url);
  ASSERT_THAT(info, IsOk());
  EXPECT_EQ((*info)->new_key_allowed(), true);

  // new_key_allowed true -> true is allowed.
  ASSERT_THAT(store.AddKeyTypeManager(absl::make_unique<AesGcmKeyManager>(),
                                      /*new_key_allowed=*/true),
              IsOk());
  info = store.Get(type_url);
  ASSERT_THAT(info, IsOk());
  EXPECT_EQ((*info)->new_key_allowed(), true);

  // new_key_allowed true -> false is allowed.
  ASSERT_THAT(store.AddKeyTypeManager(absl::make_unique<AesGcmKeyManager>(),
                                      /*new_key_allowed=*/false),
              IsOk());
  info = store.Get(type_url);
  ASSERT_THAT(info, IsOk());
  EXPECT_EQ((*info)->new_key_allowed(), false);

  // new_key_allowed false -> false is allowed.
  ASSERT_THAT(store.AddKeyTypeManager(absl::make_unique<AesGcmKeyManager>(),
                                      /*new_key_allowed=*/false),
              IsOk());
  info = store.Get(type_url);
  ASSERT_THAT(info, IsOk());
  EXPECT_EQ((*info)->new_key_allowed(), false);

  // new_key_allowed false -> true is not allowed.
  ASSERT_THAT(store.AddKeyTypeManager(absl::make_unique<AesGcmKeyManager>(),
                                      /*new_key_allowed=*/true),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

TEST(KeyTypeInfoStoreTest, AddAsymmetricKeyTypeManagers) {
  KeyTypeInfoStore store;
  ASSERT_THAT(store.AddAsymmetricKeyTypeManagers(
                  absl::make_unique<EcdsaSignKeyManager>(),
                  absl::make_unique<EcdsaVerifyKeyManager>(),
                  /*new_key_allowed=*/true),
              IsOk());

  {
    std::string private_type_url = EcdsaSignKeyManager().get_key_type();
    util::StatusOr<KeyTypeInfoStore::Info*> info = store.Get(private_type_url);
    ASSERT_THAT(info, IsOk());

    util::StatusOr<const KeyManager<PublicKeySign>*> manager =
        (*info)->get_key_manager<PublicKeySign>(private_type_url);
    ASSERT_THAT(manager, IsOk());
    EXPECT_EQ((*manager)->get_key_type(), private_type_url);
  }
  {
    std::string public_type_url = EcdsaVerifyKeyManager().get_key_type();
    util::StatusOr<KeyTypeInfoStore::Info*> info = store.Get(public_type_url);
    ASSERT_THAT(info, IsOk());

    util::StatusOr<const KeyManager<PublicKeyVerify>*> manager =
        (*info)->get_key_manager<PublicKeyVerify>(public_type_url);
    ASSERT_THAT(manager, IsOk());
    EXPECT_EQ((*manager)->get_key_type(), public_type_url);
  }
}

TEST(KeyTypeInfoStoreTest, AddAsymmetricKeyTypeManagersAlreadyExists) {
  {
    KeyTypeInfoStore store;
    ASSERT_THAT(
        store.AddKeyTypeManager(absl::make_unique<EcdsaSignKeyManager>(),
                                /*new_key_allowed=*/true),
        IsOk());
    EXPECT_THAT(store.AddAsymmetricKeyTypeManagers(
                    absl::make_unique<EcdsaSignKeyManager>(),
                    absl::make_unique<EcdsaVerifyKeyManager>(),
                    /*new_key_allowed=*/true),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
  {
    KeyTypeInfoStore store;
    ASSERT_THAT(
        store.AddKeyTypeManager(absl::make_unique<EcdsaVerifyKeyManager>(),
                                /*new_key_allowed=*/true),
        IsOk());
    EXPECT_THAT(store.AddAsymmetricKeyTypeManagers(
                    absl::make_unique<EcdsaSignKeyManager>(),
                    absl::make_unique<EcdsaVerifyKeyManager>(),
                    /*new_key_allowed=*/true),
                StatusIs(absl::StatusCode::kInvalidArgument));
  }
  {
    KeyTypeInfoStore store;
    EXPECT_THAT(store.AddAsymmetricKeyTypeManagers(
                    absl::make_unique<EcdsaSignKeyManager>(),
                    absl::make_unique<EcdsaVerifyKeyManager>(),
                    /*new_key_allowed=*/true),
                IsOk());
    EXPECT_THAT(store.AddAsymmetricKeyTypeManagers(
                    absl::make_unique<EcdsaSignKeyManager>(),
                    absl::make_unique<EcdsaVerifyKeyManager>(),
                    /*new_key_allowed=*/true),
                IsOk());
  }
}

TEST(KeyTypeInfoStoreTest, AddAsymmetricKeyTypeManagersAndChangeNewKeyAllowed) {
  KeyTypeInfoStore store;
  ASSERT_THAT(store.AddAsymmetricKeyTypeManagers(
                  absl::make_unique<EcdsaSignKeyManager>(),
                  absl::make_unique<EcdsaVerifyKeyManager>(),
                  /*new_key_allowed=*/true),
              IsOk());

  std::string private_type_url = EcdsaSignKeyManager().get_key_type();
  std::string public_type_url = EcdsaVerifyKeyManager().get_key_type();

  util::StatusOr<KeyTypeInfoStore::Info*> private_info =
      store.Get(private_type_url);
  ASSERT_THAT(private_info, IsOk());
  EXPECT_EQ((*private_info)->new_key_allowed(), true);
  util::StatusOr<KeyTypeInfoStore::Info*> public_info =
      store.Get(public_type_url);
  ASSERT_THAT(public_info, IsOk());
  EXPECT_EQ((*public_info)->new_key_allowed(), true);

  // new_key_allowed true -> true is allowed.
  ASSERT_THAT(store.AddAsymmetricKeyTypeManagers(
                  absl::make_unique<EcdsaSignKeyManager>(),
                  absl::make_unique<EcdsaVerifyKeyManager>(),
                  /*new_key_allowed=*/true),
              IsOk());
  private_info = store.Get(private_type_url);
  ASSERT_THAT(private_info, IsOk());
  EXPECT_EQ((*private_info)->new_key_allowed(), true);
  public_info = store.Get(public_type_url);
  ASSERT_THAT(public_info, IsOk());
  EXPECT_EQ((*public_info)->new_key_allowed(), true);

  // new_key_allowed true -> false is allowed.
  ASSERT_THAT(store.AddAsymmetricKeyTypeManagers(
                  absl::make_unique<EcdsaSignKeyManager>(),
                  absl::make_unique<EcdsaVerifyKeyManager>(),
                  /*new_key_allowed=*/false),
              IsOk());
  private_info = store.Get(private_type_url);
  ASSERT_THAT(private_info, IsOk());
  EXPECT_EQ((*private_info)->new_key_allowed(), false);
  public_info = store.Get(public_type_url);
  ASSERT_THAT(public_info, IsOk());
  EXPECT_EQ((*public_info)->new_key_allowed(), true);

  // new_key_allowed false -> false is allowed.
  ASSERT_THAT(store.AddAsymmetricKeyTypeManagers(
                  absl::make_unique<EcdsaSignKeyManager>(),
                  absl::make_unique<EcdsaVerifyKeyManager>(),
                  /*new_key_allowed=*/false),
              IsOk());
  private_info = store.Get(private_type_url);
  ASSERT_THAT(private_info, IsOk());
  EXPECT_EQ((*private_info)->new_key_allowed(), false);
  public_info = store.Get(public_type_url);
  ASSERT_THAT(public_info, IsOk());
  EXPECT_EQ((*public_info)->new_key_allowed(), true);

  // new_key_allowed false -> true is not allowed.
  ASSERT_THAT(store.AddAsymmetricKeyTypeManagers(
                  absl::make_unique<EcdsaSignKeyManager>(),
                  absl::make_unique<EcdsaVerifyKeyManager>(),
                  /*new_key_allowed=*/true),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

TEST(KeyTypeInfoStoreTest, AddKeyManager) {
  KeyTypeInfoStore store;
  AesGcmKeyManager manager;
  ASSERT_THAT(store.AddKeyManager(MakeKeyManager<Aead>(&manager),
                                  /*new_key_allowed=*/true),
              IsOk());

  std::string type_url = manager.get_key_type();
  util::StatusOr<KeyTypeInfoStore::Info*> info = store.Get(type_url);
  ASSERT_THAT(info, IsOk());

  util::StatusOr<const KeyManager<Aead>*> got_manager =
      (*info)->get_key_manager<Aead>(type_url);
  ASSERT_THAT(got_manager, IsOk());
  EXPECT_EQ((*got_manager)->get_key_type(), type_url);
}

TEST(KeyTypeInfoStoreTest, AddKeyManagerAndChangeNewKeyAllowed) {
  KeyTypeInfoStore store;
  AesGcmKeyManager manager;
  ASSERT_THAT(store.AddKeyManager(MakeKeyManager<Aead>(&manager),
                                  /*new_key_allowed=*/true),
              IsOk());

  std::string type_url = manager.get_key_type();
  util::StatusOr<KeyTypeInfoStore::Info*> info = store.Get(type_url);
  ASSERT_THAT(info, IsOk());
  EXPECT_EQ((*info)->new_key_allowed(), true);

  // new_key_allowed true -> true is allowed.
  ASSERT_THAT(store.AddKeyManager(MakeKeyManager<Aead>(&manager),
                                  /*new_key_allowed=*/true),
              IsOk());
  info = store.Get(type_url);
  ASSERT_THAT(info, IsOk());
  EXPECT_EQ((*info)->new_key_allowed(), true);

  // new_key_allowed true -> false is allowed.
  ASSERT_THAT(store.AddKeyManager(MakeKeyManager<Aead>(&manager),
                                  /*new_key_allowed=*/false),
              IsOk());
  info = store.Get(type_url);
  ASSERT_THAT(info, IsOk());
  EXPECT_EQ((*info)->new_key_allowed(), false);

  // new_key_allowed false -> false is allowed.
  ASSERT_THAT(store.AddKeyManager(MakeKeyManager<Aead>(&manager),
                                  /*new_key_allowed=*/false),
              IsOk());
  info = store.Get(type_url);
  ASSERT_THAT(info, IsOk());
  EXPECT_EQ((*info)->new_key_allowed(), false);

  // new_key_allowed false -> true is not allowed.
  ASSERT_THAT(store.AddKeyManager(MakeKeyManager<Aead>(&manager),
                                  /*new_key_allowed=*/true),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

TEST(KeyTypeInfoStoreTest, Get) {
  KeyTypeInfoStore store;
  ASSERT_THAT(store.AddKeyTypeManager(absl::make_unique<AesGcmKeyManager>(),
                                      /*new_key_allowed=*/true),
              IsOk());
  util::StatusOr<KeyTypeInfoStore::Info*> info =
      store.Get(AesGcmKeyManager().get_key_type());
  EXPECT_THAT(info, IsOk());

  EXPECT_THAT(store.Get("nonexistent.type.url").status(),
              StatusIs(absl::StatusCode::kNotFound));
}

TEST(KeyTypeInfoStoreTest, IsEmpty) {
  KeyTypeInfoStore store;
  EXPECT_EQ(store.IsEmpty(), true);

  ASSERT_THAT(store.AddKeyTypeManager(absl::make_unique<AesGcmKeyManager>(),
                                      /*new_key_allowed=*/true),
              IsOk());
  EXPECT_THAT(store.IsEmpty(), false);
}

TEST(KeyTypeInfoStoreInfoTest, ConstructWithKeyTypeManager) {
  KeyTypeInfoStore::Info info(absl::make_unique<AesGcmKeyManager>().release(),
                              /*new_key_allowed=*/false);

  EXPECT_EQ(info.key_manager_type_index(),
            std::type_index(typeid(AesGcmKeyManager)));
  EXPECT_EQ(info.public_key_type_manager_type_index(), absl::nullopt);

  EXPECT_EQ(info.new_key_allowed(), false);
  info.set_new_key_allowed(true);
  EXPECT_EQ(info.new_key_allowed(), true);

  std::string type_url = AesGcmKeyManager().get_key_type();
  util::StatusOr<const KeyManager<Aead>*> aead_manager =
      info.get_key_manager<Aead>(type_url);
  ASSERT_THAT(aead_manager, IsOk());
  EXPECT_EQ((*aead_manager)->DoesSupport(type_url), true);
  util::StatusOr<const KeyManager<CordAead>*> cord_aead_manager =
      info.get_key_manager<CordAead>(type_url);
  ASSERT_THAT(aead_manager, IsOk());
  EXPECT_EQ((*aead_manager)->DoesSupport(type_url), true);

  AesGcmKeyFormat format;
  format.set_key_size(32);
  EXPECT_THAT(info.key_factory().NewKeyData(format.SerializeAsString()),
              IsOk());

  EXPECT_EQ((bool)info.key_deriver(), true);
}

TEST(KeyTypeInfoStoreInfoTest, ConstructWithAsymmetricKeyTypeManagers) {
  KeyTypeInfoStore::Info info(
      absl::make_unique<EcdsaSignKeyManager>().release(),
      absl::make_unique<EcdsaVerifyKeyManager>().get(),
      /*new_key_allowed=*/false);

  EXPECT_EQ(info.key_manager_type_index(),
            std::type_index(typeid(EcdsaSignKeyManager)));
  EXPECT_EQ(info.public_key_type_manager_type_index(),
            std::type_index(typeid(EcdsaVerifyKeyManager)));

  EXPECT_EQ(info.new_key_allowed(), false);
  info.set_new_key_allowed(true);
  EXPECT_EQ(info.new_key_allowed(), true);

  std::string type_url = EcdsaSignKeyManager().get_key_type();
  util::StatusOr<const KeyManager<PublicKeySign>*> manager =
      info.get_key_manager<PublicKeySign>(type_url);
  ASSERT_THAT(manager, IsOk());
  EXPECT_EQ((*manager)->DoesSupport(type_url), true);

  EcdsaKeyFormat format;
  EcdsaParams* params = format.mutable_params();
  params->set_hash_type(HashType::SHA256);
  params->set_curve(EllipticCurveType::NIST_P256);
  params->set_encoding(EcdsaSignatureEncoding::DER);
  EXPECT_THAT(info.key_factory().NewKeyData(format.SerializeAsString()),
              IsOk());

  EXPECT_EQ((bool)info.key_deriver(), true);
}

TEST(KeyTypeInfoStoreInfoTest, ConstructWithKeyManager) {
  AesGcmKeyManager key_type_manager;
  std::unique_ptr<KeyManager<Aead>> manager =
      MakeKeyManager<Aead>(&key_type_manager);
  std::type_index type_index = std::type_index(typeid(*manager));
  KeyTypeInfoStore::Info info(manager.release(),
                              /*new_key_allowed=*/false);

  EXPECT_EQ(info.key_manager_type_index(), type_index);
  EXPECT_EQ(info.public_key_type_manager_type_index(), absl::nullopt);

  EXPECT_EQ(info.new_key_allowed(), false);
  info.set_new_key_allowed(true);
  EXPECT_EQ(info.new_key_allowed(), true);

  std::string type_url = AesGcmKeyManager().get_key_type();
  util::StatusOr<const KeyManager<Aead>*> got_manager =
      info.get_key_manager<Aead>(type_url);
  ASSERT_THAT(got_manager, IsOk());
  EXPECT_EQ((*got_manager)->DoesSupport(type_url), true);
  // Inserted KeyManager only supports Aead, not CordAead.
  EXPECT_THAT(info.get_key_manager<CordAead>(type_url).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));

  AesGcmKeyFormat format;
  format.set_key_size(32);
  EXPECT_THAT(info.key_factory().NewKeyData(format.SerializeAsString()),
              IsOk());

  EXPECT_EQ((bool)info.key_deriver(), false);
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
