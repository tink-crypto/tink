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
///////////////////////////////////////////////////////////////////////////////
#include "tink/core/private_key_manager_impl.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/core/key_manager_impl.h"
#include "tink/core/private_key_type_manager.h"
#include "tink/registry.h"
#include "tink/subtle/aes_gcm_boringssl.h"
#include "tink/subtle/random.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "tink/util/validation.h"
#include "proto/ecdsa.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::EcdsaKeyFormat;
using ::google::crypto::tink::EcdsaPrivateKey;
using ::google::crypto::tink::EcdsaPublicKey;
using ::google::crypto::tink::EcdsaSignatureEncoding;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Return;

// Placeholders for the primitives. We don't really want to test anything with
// these except that things compile and List<PrivatePrimitive> is never confused
// with List<PublicPrimitive> in private_key_manager_impl.
class PrivatePrimitive {};
class PublicPrimitive {};

class ExamplePrivateKeyTypeManager
    : public PrivateKeyTypeManager<EcdsaPrivateKey, EcdsaKeyFormat,
                                   EcdsaPublicKey, List<PrivatePrimitive>> {
 public:
  class PrivatePrimitiveFactory : public PrimitiveFactory<PrivatePrimitive> {
   public:
    crypto::tink::util::StatusOr<std::unique_ptr<PrivatePrimitive>> Create(
        const EcdsaPrivateKey& key) const override {
      return util::Status(absl::StatusCode::kUnimplemented, "Not implemented");
    }
  };

  ExamplePrivateKeyTypeManager()
      : PrivateKeyTypeManager(absl::make_unique<PrivatePrimitiveFactory>()) {}

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::ASYMMETRIC_PRIVATE;
  }

  MOCK_METHOD(uint32_t, get_version, (), (const, override));

  // We mock out ValidateKey and ValidateKeyFormat so that we can easily test
  // proper behavior in case they return an error.
  MOCK_METHOD(crypto::tink::util::Status, ValidateKey,
              (const EcdsaPrivateKey& key), (const, override));
  MOCK_METHOD(crypto::tink::util::Status, ValidateKeyFormat,
              (const EcdsaKeyFormat& key), (const, override));

  const std::string& get_key_type() const override { return kKeyType; }

  crypto::tink::util::StatusOr<EcdsaPrivateKey> CreateKey(
      const EcdsaKeyFormat& key_format) const override {
    EcdsaPublicKey public_key;
    *public_key.mutable_params() = key_format.params();
    EcdsaPrivateKey result;
    *result.mutable_public_key() = public_key;
    return result;
  }

  crypto::tink::util::StatusOr<EcdsaPublicKey> GetPublicKey(
      const EcdsaPrivateKey& private_key) const override {
    return private_key.public_key();
  }

 private:
  const std::string kKeyType =
      "type.googleapis.com/google.crypto.tink.EcdsaPublicKey";
};

class TestPublicKeyTypeManager
    : public KeyTypeManager<EcdsaPublicKey, void, List<PublicPrimitive>> {
 public:
  class PublicPrimitiveFactory : public PrimitiveFactory<PublicPrimitive> {
   public:
    crypto::tink::util::StatusOr<std::unique_ptr<PublicPrimitive>> Create(
        const EcdsaPublicKey& key) const override {
      return util::Status(absl::StatusCode::kUnimplemented, "Not implemented");
    }
  };

  TestPublicKeyTypeManager()
      : KeyTypeManager(absl::make_unique<PublicPrimitiveFactory>()) {}

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::ASYMMETRIC_PRIVATE;
  }

  MOCK_METHOD(uint32_t, get_version, (), (const, override));

  // We mock out ValidateKey and ValidateKeyFormat so that we can easily test
  // proper behavior in case they return an error.
  MOCK_METHOD(crypto::tink::util::Status, ValidateKey,
              (const EcdsaPublicKey& key), (const, override));

  const std::string& get_key_type() const override { return kKeyType; }

 private:
  const std::string kKeyType =
      "type.googleapis.com/google.crypto.tink.EcdsaPublicKey";
};

TEST(PrivateKeyManagerImplTest, FactoryNewKeyFromMessage) {
  ExamplePrivateKeyTypeManager private_km;
  TestPublicKeyTypeManager public_km;
  std::unique_ptr<KeyManager<PrivatePrimitive>> key_manager =
      MakePrivateKeyManager<PrivatePrimitive>(&private_km, &public_km);

  EcdsaKeyFormat key_format;
  key_format.mutable_params()->set_encoding(EcdsaSignatureEncoding::DER);
  auto key = key_manager->get_key_factory().NewKey(key_format).value();
  EXPECT_THAT(
      dynamic_cast<EcdsaPrivateKey&>(*key).public_key().params().encoding(),
      Eq(EcdsaSignatureEncoding::DER));
}

TEST(PrivateKeyManagerImplTest, GetPublicKeyData) {
  ExamplePrivateKeyTypeManager private_km;
  TestPublicKeyTypeManager public_km;
  std::unique_ptr<KeyManager<PrivatePrimitive>> key_manager =
      MakePrivateKeyManager<PrivatePrimitive>(&private_km, &public_km);

  EcdsaPrivateKey private_key;
  private_key.mutable_public_key()->mutable_params()->set_encoding(
      EcdsaSignatureEncoding::DER);

  auto key_data =
      dynamic_cast<const PrivateKeyFactory&>(key_manager->get_key_factory())
          .GetPublicKeyData(private_key.SerializeAsString())
          .value();
  ASSERT_THAT(key_data->type_url(), Eq(public_km.get_key_type()));
  EcdsaPublicKey public_key;
  public_key.ParseFromString(key_data->value());
  EXPECT_THAT(public_key.params().encoding(), Eq(EcdsaSignatureEncoding::DER));
}

TEST(PrivateKeyManagerImplTest, GetPublicKeyDataValidatePrivateKey) {
  ExamplePrivateKeyTypeManager private_km;
  TestPublicKeyTypeManager public_km;
  EXPECT_CALL(private_km, ValidateKey)
      .WillOnce(Return(util::Status(absl::StatusCode::kOutOfRange,
                                    "GetPublicKeyDataValidatePrivateKey")));

  std::unique_ptr<KeyManager<PrivatePrimitive>> key_manager =
      MakePrivateKeyManager<PrivatePrimitive>(&private_km, &public_km);

  EXPECT_THAT(
      dynamic_cast<const PrivateKeyFactory&>(key_manager->get_key_factory())
          .GetPublicKeyData(EcdsaPrivateKey().SerializeAsString())
          .status(),
      StatusIs(absl::StatusCode::kOutOfRange,
               HasSubstr("GetPublicKeyDataValidatePrivateKey")));
}

TEST(PrivateKeyManagerImplTest, PublicKeyManagerCanHaveShortLifetime) {
  ExamplePrivateKeyTypeManager private_km;
  std::unique_ptr<KeyManager<PrivatePrimitive>> key_manager;
  {
    TestPublicKeyTypeManager public_km;
    key_manager =
        MakePrivateKeyManager<PrivatePrimitive>(&private_km, &public_km);
    // Let the public_km go out of scope; the key_manager should still work.
  }

  EcdsaKeyFormat key_format;
  key_format.mutable_params()->set_encoding(EcdsaSignatureEncoding::DER);
  auto key = key_manager->get_key_factory().NewKey(key_format).value();
  EXPECT_THAT(
      dynamic_cast<EcdsaPrivateKey&>(*key).public_key().params().encoding(),
      Eq(EcdsaSignatureEncoding::DER));
}

}  // namespace

}  // namespace internal
}  // namespace tink
}  // namespace crypto
