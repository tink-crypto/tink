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

#include "tink/internal/key_gen_configuration_impl.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/key_gen_configuration.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/aes_gcm.pb.h"
#include "proto/rsa_ssa_pss.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesGcmKey;
using ::google::crypto::tink::AesGcmKeyFormat;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::RsaSsaPssKeyFormat;
using ::google::crypto::tink::RsaSsaPssParams;
using ::google::crypto::tink::RsaSsaPssPrivateKey;
using ::google::crypto::tink::RsaSsaPssPublicKey;

class FakePrimitive {
 public:
  explicit FakePrimitive(std::string s) : s_(s) {}
  std::string get() { return s_; }

 private:
  std::string s_;
};

class FakeKeyTypeManager
    : public KeyTypeManager<AesGcmKey, AesGcmKeyFormat, List<FakePrimitive>> {
 public:
  class FakePrimitiveFactory : public PrimitiveFactory<FakePrimitive> {
   public:
    util::StatusOr<std::unique_ptr<FakePrimitive>> Create(
        const AesGcmKey& key) const override {
      return absl::make_unique<FakePrimitive>(key.key_value());
    }
  };

  FakeKeyTypeManager()
      : KeyTypeManager(absl::make_unique<FakePrimitiveFactory>()) {}

  KeyData::KeyMaterialType key_material_type() const override {
    return KeyData::SYMMETRIC;
  }

  uint32_t get_version() const override { return 0; }

  const std::string& get_key_type() const override { return key_type_; }

  util::Status ValidateKey(const AesGcmKey& key) const override {
    return util::OkStatus();
  }

  util::Status ValidateKeyFormat(
      const AesGcmKeyFormat& key_format) const override {
    return util::OkStatus();
  }

  util::StatusOr<AesGcmKey> CreateKey(
      const AesGcmKeyFormat& key_format) const override {
    return AesGcmKey();
  }

  util::StatusOr<AesGcmKey> DeriveKey(
      const AesGcmKeyFormat& key_format,
      InputStream* input_stream) const override {
    return AesGcmKey();
  }

 private:
  const std::string key_type_ =
      "type.googleapis.com/google.crypto.tink.AesGcmKey";
};

TEST(KeyGenConfigurationImplTest, AddKeyTypeManager) {
  KeyGenConfiguration config;
  EXPECT_THAT(KeyGenConfigurationImpl::AddKeyTypeManager(
                  absl::make_unique<FakeKeyTypeManager>(), config),
              IsOk());
}

TEST(KeyGenConfigurationImplTest, GetKeyTypeInfoStore) {
  KeyGenConfiguration config;
  ASSERT_THAT(KeyGenConfigurationImpl::AddKeyTypeManager(
                  absl::make_unique<FakeKeyTypeManager>(), config),
              IsOk());

  std::string type_url = FakeKeyTypeManager().get_key_type();
  util::StatusOr<const KeyTypeInfoStore*> store =
      KeyGenConfigurationImpl::GetKeyTypeInfoStore(config);
  ASSERT_THAT(store, IsOk());
  util::StatusOr<const KeyTypeInfoStore::Info*> info = (*store)->Get(type_url);
  ASSERT_THAT(info, IsOk());

  util::StatusOr<const KeyManager<FakePrimitive>*> key_manager =
      (*info)->get_key_manager<FakePrimitive>(type_url);
  ASSERT_THAT(key_manager, IsOk());
  EXPECT_EQ((*key_manager)->get_key_type(), type_url);
}

TEST(KeyGenConfigurationImplTest, GetKeyTypeInfoStoreMissingInfoFails) {
  KeyGenConfiguration config;
  util::StatusOr<const KeyTypeInfoStore*> store =
      KeyGenConfigurationImpl::GetKeyTypeInfoStore(config);
  ASSERT_THAT(store, IsOk());
  EXPECT_THAT((*store)->Get("i.do.not.exist").status(),
              StatusIs(absl::StatusCode::kNotFound));
}

class FakeSignKeyManager
    : public PrivateKeyTypeManager<RsaSsaPssPrivateKey, RsaSsaPssKeyFormat,
                                   RsaSsaPssPublicKey, List<PublicKeySign>> {
 public:
  class PublicKeySignFactory : public PrimitiveFactory<PublicKeySign> {
   public:
    util::StatusOr<std::unique_ptr<PublicKeySign>> Create(
        const RsaSsaPssPrivateKey& key) const override {
      return {absl::make_unique<test::DummyPublicKeySign>("a public key sign")};
    }
  };

  explicit FakeSignKeyManager()
      : PrivateKeyTypeManager(absl::make_unique<PublicKeySignFactory>()) {}

  KeyData::KeyMaterialType key_material_type() const override {
    return KeyData::ASYMMETRIC_PRIVATE;
  }

  uint32_t get_version() const override { return 0; }

  const std::string& get_key_type() const override { return key_type_; }

  util::Status ValidateKey(const RsaSsaPssPrivateKey& key) const override {
    return util::OkStatus();
  }

  util::Status ValidateKeyFormat(
      const RsaSsaPssKeyFormat& key_format) const override {
    return util::OkStatus();
  }

  util::StatusOr<RsaSsaPssPrivateKey> CreateKey(
      const RsaSsaPssKeyFormat& key_format) const override {
    return RsaSsaPssPrivateKey();
  }

  util::StatusOr<RsaSsaPssPrivateKey> DeriveKey(
      const RsaSsaPssKeyFormat& key_format,
      InputStream* input_stream) const override {
    return RsaSsaPssPrivateKey();
  }

  util::StatusOr<RsaSsaPssPublicKey> GetPublicKey(
      const RsaSsaPssPrivateKey& private_key) const override {
    return private_key.public_key();
  }

 private:
  const std::string key_type_ = "some.sign.key.type";
};

class FakeVerifyKeyManager
    : public KeyTypeManager<RsaSsaPssPublicKey, void, List<PublicKeyVerify>> {
 public:
  class PublicKeyVerifyFactory : public PrimitiveFactory<PublicKeyVerify> {
   public:
    util::StatusOr<std::unique_ptr<PublicKeyVerify>> Create(
        const RsaSsaPssPublicKey& key) const override {
      return {
          absl::make_unique<test::DummyPublicKeyVerify>("a public key verify")};
    }
  };

  explicit FakeVerifyKeyManager()
      : KeyTypeManager(absl::make_unique<PublicKeyVerifyFactory>()) {}

  KeyData::KeyMaterialType key_material_type() const override {
    return KeyData::ASYMMETRIC_PUBLIC;
  }

  uint32_t get_version() const override { return 0; }

  const std::string& get_key_type() const override { return key_type_; }

  util::Status ValidateKey(const RsaSsaPssPublicKey& key) const override {
    return util::OkStatus();
  }

  util::Status ValidateParams(const RsaSsaPssParams& params) const {
    return util::OkStatus();
  }

 private:
  const std::string key_type_ = "some.verify.key.type";
};

TEST(KeyGenConfigurationImplTest, AddAsymmetricKeyManagers) {
  KeyGenConfiguration config;
  EXPECT_THAT(KeyGenConfigurationImpl::AddAsymmetricKeyManagers(
                  absl::make_unique<FakeSignKeyManager>(),
                  absl::make_unique<FakeVerifyKeyManager>(), config),
              IsOk());
}

TEST(KeyGenConfigurationImplTest, GetKeyTypeInfoStoreAsymmetric) {
  KeyGenConfiguration config;
  ASSERT_THAT(KeyGenConfigurationImpl::AddAsymmetricKeyManagers(
                  absl::make_unique<FakeSignKeyManager>(),
                  absl::make_unique<FakeVerifyKeyManager>(), config),
              IsOk());

  {
    std::string type_url = FakeSignKeyManager().get_key_type();
    util::StatusOr<const KeyTypeInfoStore*> store =
        KeyGenConfigurationImpl::GetKeyTypeInfoStore(config);
    ASSERT_THAT(store, IsOk());
    util::StatusOr<const KeyTypeInfoStore::Info*> info =
        (*store)->Get(type_url);
    ASSERT_THAT(info, IsOk());

    util::StatusOr<const KeyManager<PublicKeySign>*> key_manager =
        (*info)->get_key_manager<PublicKeySign>(type_url);
    ASSERT_THAT(key_manager, IsOk());
    EXPECT_EQ((*key_manager)->get_key_type(), type_url);
  }
  {
    std::string type_url = FakeVerifyKeyManager().get_key_type();
    util::StatusOr<const KeyTypeInfoStore*> store =
        KeyGenConfigurationImpl::GetKeyTypeInfoStore(config);
    ASSERT_THAT(store, IsOk());
    util::StatusOr<const KeyTypeInfoStore::Info*> info =
        (*store)->Get(type_url);
    ASSERT_THAT(info, IsOk());

    util::StatusOr<const KeyManager<PublicKeyVerify>*> key_manager =
        (*info)->get_key_manager<PublicKeyVerify>(type_url);
    ASSERT_THAT(key_manager, IsOk());
    EXPECT_EQ((*key_manager)->get_key_type(), type_url);
  }
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
