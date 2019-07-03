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

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/core/internal_private_key_manager.h"
#include "tink/core/key_manager_impl.h"
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

class ExampleInternalPrivateKeyManager
    : public InternalPrivateKeyManager<EcdsaPrivateKey, EcdsaKeyFormat,
                                       EcdsaPublicKey, List<PrivatePrimitive>> {
 public:
  class PrivatePrimitiveFactory : public PrimitiveFactory<PrivatePrimitive> {
   public:
    crypto::tink::util::StatusOr<std::unique_ptr<PrivatePrimitive>> Create(
        const EcdsaPrivateKey& key) const override {
      return util::Status(util::error::UNIMPLEMENTED, "Not implemented");
    }
  };

  ExampleInternalPrivateKeyManager()
      : InternalPrivateKeyManager(
            absl::make_unique<PrivatePrimitiveFactory>()) {}

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::ASYMMETRIC_PRIVATE;
  }

  MOCK_CONST_METHOD0(get_version, uint32_t());

  // We mock out ValidateKey and ValidateKeyFormat so that we can easily test
  // proper behavior in case they return an error.
  MOCK_CONST_METHOD1(ValidateKey,
                     crypto::tink::util::Status(const EcdsaPrivateKey& key));
  MOCK_CONST_METHOD1(ValidateKeyFormat,
                     crypto::tink::util::Status(const EcdsaKeyFormat& key));

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

class ExampleInternalPublicKeyManager
    : public InternalKeyManager<EcdsaPublicKey, void, List<PublicPrimitive>> {
 public:
  class PublicPrimitiveFactory : public PrimitiveFactory<PublicPrimitive> {
   public:
    crypto::tink::util::StatusOr<std::unique_ptr<PublicPrimitive>> Create(
        const EcdsaPublicKey& key) const override {
      return util::Status(util::error::UNIMPLEMENTED, "Not implemented");
    }
  };

  ExampleInternalPublicKeyManager()
      : InternalKeyManager(absl::make_unique<PublicPrimitiveFactory>()) {}

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::ASYMMETRIC_PRIVATE;
  }

  MOCK_CONST_METHOD0(get_version, uint32_t());

  // We mock out ValidateKey and ValidateKeyFormat so that we can easily test
  // proper behavior in case they return an error.
  MOCK_CONST_METHOD1(ValidateKey,
                     crypto::tink::util::Status(const EcdsaPublicKey& key));

  const std::string& get_key_type() const override { return kKeyType; }

 private:
  const std::string kKeyType =
      "type.googleapis.com/google.crypto.tink.EcdsaPublicKey";
};

TEST(PrivateKeyManagerImplTest, FactoryNewKeyFromMessage) {
  ExampleInternalPrivateKeyManager private_km;
  ExampleInternalPublicKeyManager public_km;
  std::unique_ptr<KeyManager<PrivatePrimitive>> key_manager =
      MakePrivateKeyManager<PrivatePrimitive>(&private_km, &public_km);

  EcdsaKeyFormat key_format;
  key_format.mutable_params()->set_encoding(EcdsaSignatureEncoding::DER);
  auto key = key_manager->get_key_factory().NewKey(key_format).ValueOrDie();
  EXPECT_THAT(
      dynamic_cast<EcdsaPrivateKey&>(*key).public_key().params().encoding(),
      Eq(EcdsaSignatureEncoding::DER));
}

TEST(PrivateKeyManagerImplTest, GetPublicKeyData) {
  ExampleInternalPrivateKeyManager private_km;
  ExampleInternalPublicKeyManager public_km;
  std::unique_ptr<KeyManager<PrivatePrimitive>> key_manager =
      MakePrivateKeyManager<PrivatePrimitive>(&private_km, &public_km);

  EcdsaPrivateKey private_key;
  private_key.mutable_public_key()->mutable_params()->set_encoding(
      EcdsaSignatureEncoding::DER);

  auto key_data =
      dynamic_cast<const PrivateKeyFactory&>(key_manager->get_key_factory())
          .GetPublicKeyData(private_key.SerializeAsString())
          .ValueOrDie();
  EcdsaPublicKey public_key;
  public_key.ParseFromString(key_data->value());
  EXPECT_THAT(public_key.params().encoding(), Eq(EcdsaSignatureEncoding::DER));
}

TEST(PrivateKeyManagerImplTest, GetPublicKeyDataValidatePrivateKey) {
  ExampleInternalPrivateKeyManager private_km;
  ExampleInternalPublicKeyManager public_km;
  EXPECT_CALL(private_km, ValidateKey)
      .WillOnce(Return(ToStatusF(util::error::OUT_OF_RANGE,
                                 "GetPublicKeyDataValidatePrivateKey")));

  std::unique_ptr<KeyManager<PrivatePrimitive>> key_manager =
      MakePrivateKeyManager<PrivatePrimitive>(&private_km, &public_km);

  EXPECT_THAT(
      dynamic_cast<const PrivateKeyFactory&>(key_manager->get_key_factory())
          .GetPublicKeyData(EcdsaPrivateKey().SerializeAsString())
          .status(),
      StatusIs(util::error::OUT_OF_RANGE,
               HasSubstr("GetPublicKeyDataValidatePrivateKey")));
}

TEST(PrivateKeyManagerImplTest, GetPublicKeyDataValidatePublicKey) {
  ExampleInternalPrivateKeyManager private_km;
  ExampleInternalPublicKeyManager public_km;
  EXPECT_CALL(public_km, ValidateKey)
      .WillOnce(Return(ToStatusF(util::error::OUT_OF_RANGE,
                                 "GetPublicKeyDataValidatePublicKey")));

  std::unique_ptr<KeyManager<PrivatePrimitive>> key_manager =
      MakePrivateKeyManager<PrivatePrimitive>(&private_km, &public_km);

  EXPECT_THAT(
      dynamic_cast<const PrivateKeyFactory&>(key_manager->get_key_factory())
          .GetPublicKeyData(EcdsaPrivateKey().SerializeAsString())
          .status(),
      StatusIs(util::error::OUT_OF_RANGE,
               HasSubstr("GetPublicKeyDataValidatePublicKey")));
}

}  // namespace

}  // namespace internal
}  // namespace tink
}  // namespace crypto
