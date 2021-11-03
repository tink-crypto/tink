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

#include "tink/core/key_manager_impl.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/aead.h"
#include "tink/subtle/aes_gcm_boringssl.h"
#include "tink/subtle/random.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "tink/util/validation.h"
#include "proto/aes_gcm.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesGcmKey;
using ::google::crypto::tink::AesGcmKeyFormat;
using ::google::crypto::tink::KeyData;
using ::testing::_;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::Return;
using ::testing::SizeIs;

// A class for testing. We will construct objects from an aead key, so that we
// can check that a keymanager can handle multiple primitives. It is really
// insecure, as it does nothing except provide access to the key.
class AeadVariant {
 public:
  explicit AeadVariant(std::string s) : s_(s) {}

  std::string get() { return s_; }

 private:
  std::string s_;
};

class ExampleKeyTypeManager : public KeyTypeManager<AesGcmKey, AesGcmKeyFormat,
                                                    List<Aead, AeadVariant>> {
 public:
  class AeadFactory : public PrimitiveFactory<Aead> {
   public:
    crypto::tink::util::StatusOr<std::unique_ptr<Aead>> Create(
        const AesGcmKey& key) const override {
      // Ignore the key and returned one with a fixed size for this test.
      return {subtle::AesGcmBoringSsl::New(
          util::SecretDataFromStringView(key.key_value()))};
    }
  };

  class AeadVariantFactory : public PrimitiveFactory<AeadVariant> {
   public:
    crypto::tink::util::StatusOr<std::unique_ptr<AeadVariant>> Create(
        const AesGcmKey& key) const override {
      return absl::make_unique<AeadVariant>(key.key_value());
    }
  };

  ExampleKeyTypeManager()
      : KeyTypeManager(absl::make_unique<AeadFactory>(),
                       absl::make_unique<AeadVariantFactory>()) {}

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::SYMMETRIC;
  }

  MOCK_METHOD(uint32_t, get_version, (), (const, override));

  // We mock out ValidateKey, ValidateKeyFormat, and DeriveKey so that we can
  // easily test proper behavior in case they return an error.
  MOCK_METHOD(crypto::tink::util::Status, ValidateKey, (const AesGcmKey& key),
              (const, override));
  MOCK_METHOD(crypto::tink::util::Status, ValidateKeyFormat,
              (const AesGcmKeyFormat& key), (const, override));
  MOCK_METHOD(crypto::tink::util::StatusOr<AesGcmKey>, DeriveKey,
              (const KeyFormatProto& key_format, InputStream* input_stream),
              (const, override));

  const std::string& get_key_type() const override { return kKeyType; }

  crypto::tink::util::StatusOr<AesGcmKey> CreateKey(
      const AesGcmKeyFormat& key_format) const override {
    AesGcmKey result;
    result.set_key_value(subtle::Random::GetRandomBytes(key_format.key_size()));
    return result;
  }

 private:
  const std::string kKeyType =
      "type.googleapis.com/google.crypto.tink.AesGcmKey";
};

TEST(KeyManagerImplTest, FactoryNewKeyFromMessage) {
  ExampleKeyTypeManager internal_km;
  std::unique_ptr<KeyManager<AeadVariant>> key_manager =
      MakeKeyManager<AeadVariant>(&internal_km);

  AesGcmKeyFormat key_format;
  key_format.set_key_size(16);
  auto key = key_manager->get_key_factory().NewKey(key_format).ValueOrDie();

  EXPECT_THAT(dynamic_cast<AesGcmKey&>(*key).key_value(), SizeIs(16));
}

TEST(KeyManagerImplTest, FactoryNewKeyFromStringView) {
  ExampleKeyTypeManager internal_km;
  std::unique_ptr<KeyManager<AeadVariant>> key_manager =
      MakeKeyManager<AeadVariant>(&internal_km);

  AesGcmKeyFormat key_format;
  key_format.set_key_size(16);
  auto key = key_manager->get_key_factory()
                 .NewKey(key_format.SerializeAsString())
                 .ValueOrDie();

  EXPECT_THAT(dynamic_cast<AesGcmKey&>(*key).key_value(), SizeIs(16));
}

TEST(KeyManagerImplTest, FactoryNewKeyFromKeyData) {
  ExampleKeyTypeManager internal_km;
  std::unique_ptr<KeyManager<AeadVariant>> key_manager =
      MakeKeyManager<AeadVariant>(&internal_km);

  AesGcmKeyFormat key_format;
  key_format.set_key_size(16);
  auto key_data = *key_manager->get_key_factory()
                       .NewKeyData(key_format.SerializeAsString())
                       .ValueOrDie();

  AesGcmKey key;
  key.ParseFromString(key_data.value());
  EXPECT_THAT(key.key_value(), SizeIs(16));
}

TEST(KeyManagerImplTest, FactoryNewKeyFromMessageCallsValidate) {
  ExampleKeyTypeManager internal_km;
  std::unique_ptr<KeyManager<AeadVariant>> key_manager =
      MakeKeyManager<AeadVariant>(&internal_km);

  AesGcmKeyFormat key_format;
  key_format.set_key_size(16);
  EXPECT_CALL(internal_km, ValidateKeyFormat(_))
      .WillOnce(Return(util::Status(absl::StatusCode::kOutOfRange,
                                    "FactoryNewKeyFromMessageCallsValidate")));
  EXPECT_THAT(key_manager->get_key_factory().NewKey(key_format).status(),
              StatusIs(absl::StatusCode::kOutOfRange,
                       HasSubstr("FactoryNewKeyFromMessageCallsValidate")));
}

TEST(KeyManagerImplTest, FactoryNewKeyFromStringViewCallsValidate) {
  ExampleKeyTypeManager internal_km;
  std::unique_ptr<KeyManager<AeadVariant>> key_manager =
      MakeKeyManager<AeadVariant>(&internal_km);

  AesGcmKeyFormat key_format;
  key_format.set_key_size(16);
  EXPECT_CALL(internal_km, ValidateKeyFormat(_))
      .WillOnce(
          Return(util::Status(absl::StatusCode::kOutOfRange,
                              "FactoryNewKeyFromStringViewCallsValidate")));
  EXPECT_THAT(key_manager->get_key_factory()
                  .NewKey(key_format.SerializeAsString())
                  .status(),
              StatusIs(absl::StatusCode::kOutOfRange,
                       HasSubstr("FactoryNewKeyFromStringViewCallsValidate")));
}

TEST(KeyManagerImplTest, FactoryNewKeyFromKeyDataCallsValidate) {
  ExampleKeyTypeManager internal_km;
  std::unique_ptr<KeyManager<AeadVariant>> key_manager =
      MakeKeyManager<AeadVariant>(&internal_km);

  AesGcmKeyFormat key_format;
  key_format.set_key_size(16);
  EXPECT_CALL(internal_km, ValidateKeyFormat(_))
      .WillOnce(Return(util::Status(absl::StatusCode::kOutOfRange,
                                    "FactoryNewKeyFromKeyDataCallsValidate")));
  EXPECT_THAT(key_manager->get_key_factory()
                  .NewKeyData(key_format.SerializeAsString())
                  .status(),
              StatusIs(absl::StatusCode::kOutOfRange,
                       HasSubstr("FactoryNewKeyFromKeyDataCallsValidate")));
}

TEST(CreateDeriverFunctionForTest, KeyMaterialAndKeyType) {
  ExampleKeyTypeManager internal_km;
  EXPECT_CALL(internal_km, DeriveKey(_, _)).
      WillOnce(Return(AesGcmKey()));
  auto deriver = CreateDeriverFunctionFor(&internal_km);

  AesGcmKeyFormat key_format;
  key_format.set_key_size(16);
  auto key_or = deriver(key_format.SerializeAsString(), nullptr);
  ASSERT_THAT(key_or.status(), IsOk());
  EXPECT_THAT(key_or.ValueOrDie().key_material_type(),
              Eq(ExampleKeyTypeManager().key_material_type()));
  EXPECT_THAT(key_or.ValueOrDie().type_url(),
              Eq(ExampleKeyTypeManager().get_key_type()));
}

TEST(CreateDeriverFunctionForTest, UseParametersAndReturnValue) {
  crypto::tink::util::IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdefghijklmnop")};
  ExampleKeyTypeManager internal_km;
  AesGcmKeyFormat key_format;
  key_format.set_key_size(9);

  EXPECT_CALL(internal_km, DeriveKey(_, _))
      .WillOnce([](const AesGcmKeyFormat& format, InputStream* randomness)
                    -> crypto::tink::util::StatusOr<AesGcmKey> {
        auto bytes_or = ReadBytesFromStream(format.key_size(), randomness);
        if (!bytes_or.ok()) {
          return bytes_or.status();
        }
        AesGcmKey key;
        key.set_key_value(bytes_or.ValueOrDie());
        return key;
      });

  auto deriver = CreateDeriverFunctionFor(&internal_km);
  auto key_or = deriver(key_format.SerializeAsString(), &input_stream);
  AesGcmKey result;
  result.ParseFromString(key_or.ValueOrDie().value());
  // Length 9 prefix of the above string.
  EXPECT_THAT(result.key_value(), Eq("012345678"));
}

TEST(CreateDeriverFunctionForTest, ValidateKeyFormatIsCalled) {
  ExampleKeyTypeManager internal_km;
  EXPECT_CALL(internal_km, ValidateKeyFormat(_))
      .WillOnce(Return(util::Status(
          absl::StatusCode::kOutOfRange,
          "CreateDeriverFunctionForTest ValidateKeyFormatIsCalled")));
  auto deriver = CreateDeriverFunctionFor(&internal_km);

  EXPECT_THAT(
      deriver(AesGcmKeyFormat().SerializeAsString(), nullptr).status(),
      StatusIs(
          absl::StatusCode::kOutOfRange,
          HasSubstr("CreateDeriverFunctionForTest ValidateKeyFormatIsCalled")));
}

TEST(CreateDeriverFunctionForTest, ValidateKeyIsCalled) {
  ExampleKeyTypeManager internal_km;
  EXPECT_CALL(internal_km, DeriveKey(_, _)).
      WillOnce(Return(AesGcmKey()));
  EXPECT_CALL(internal_km, ValidateKey(_))
      .WillOnce(Return(
          util::Status(absl::StatusCode::kOutOfRange,
                       "CreateDeriverFunctionForTest ValidateKeyIsCalled")));

  auto deriver = CreateDeriverFunctionFor(&internal_km);

  EXPECT_THAT(
      deriver(AesGcmKeyFormat().SerializeAsString(), nullptr).status(),
      StatusIs(
          absl::StatusCode::kOutOfRange,
          HasSubstr("CreateDeriverFunctionForTest ValidateKeyIsCalled")));
}

TEST(KeyManagerImplTest, GetPrimitiveAead) {
  ExampleKeyTypeManager internal_km;
  std::unique_ptr<KeyManager<Aead>> key_manager =
      MakeKeyManager<Aead>(&internal_km);

  AesGcmKeyFormat key_format;
  key_format.set_key_size(16);

  auto key_data = *key_manager->get_key_factory()
                       .NewKeyData(key_format.SerializeAsString())
                       .ValueOrDie();

  auto aead = key_manager->GetPrimitive(key_data).ValueOrDie();
  std::string encryption = aead->Encrypt("Hi", "aad").ValueOrDie();
  std::string decryption = aead->Decrypt(encryption, "aad").ValueOrDie();
  EXPECT_THAT(decryption, Eq("Hi"));
}

TEST(KeyManagerImplTest, GetPrimitiveAeadVariant) {
  ExampleKeyTypeManager internal_km;
  std::unique_ptr<KeyManager<AeadVariant>> key_manager =
      MakeKeyManager<AeadVariant>(&internal_km);

  AesGcmKeyFormat key_format;
  key_format.set_key_size(16);
  auto key_data = *key_manager->get_key_factory()
                       .NewKeyData(key_format.SerializeAsString())
                       .ValueOrDie();

  AesGcmKey key;
  key.ParseFromString(key_data.value());
  auto aead_variant = key_manager->GetPrimitive(key_data).ValueOrDie();
  EXPECT_THAT(aead_variant->get(), Eq(key.key_value()));
}

TEST(KeyManagerImplTest, GetPrimitiveFromKey) {
  ExampleKeyTypeManager internal_km;
  std::unique_ptr<KeyManager<Aead>> key_manager =
      MakeKeyManager<Aead>(&internal_km);

  AesGcmKeyFormat key_format;
  key_format.set_key_size(16);
  auto key = key_manager->get_key_factory()
                 .NewKey(key_format.SerializeAsString())
                 .ValueOrDie();

  auto aead = key_manager->GetPrimitive(*key).ValueOrDie();
  std::string encryption = aead->Encrypt("Hi", "aad").ValueOrDie();
  std::string decryption = aead->Decrypt(encryption, "aad").ValueOrDie();
  EXPECT_THAT(decryption, Eq("Hi"));
}

TEST(KeyManagerImplTest, GetKeyType) {
  ExampleKeyTypeManager internal_km;
  std::unique_ptr<KeyManager<Aead>> key_manager =
      MakeKeyManager<Aead>(&internal_km);
  EXPECT_THAT(key_manager->get_key_type(), Eq(internal_km.get_key_type()));
}

TEST(KeyManagerImplTest, GetVersion) {
  ExampleKeyTypeManager internal_km;
  std::unique_ptr<KeyManager<Aead>> key_manager =
      MakeKeyManager<Aead>(&internal_km);
  EXPECT_CALL(internal_km, get_version()).WillOnce(Return(121351));
  EXPECT_THAT(121351, Eq(internal_km.get_version()));
}

TEST(KeyManagerImplTest, DoesSupport) {
  ExampleKeyTypeManager internal_km;
  std::unique_ptr<KeyManager<Aead>> key_manager =
      MakeKeyManager<Aead>(&internal_km);
  EXPECT_TRUE(key_manager->DoesSupport(internal_km.get_key_type()));
  // Check with first and last letter removed.
  EXPECT_FALSE(key_manager->DoesSupport(
      "type.googleapis.com/google.crypto.tink.AesGcmKe"));
  EXPECT_FALSE(key_manager->DoesSupport(
      "ype.googleapis.com/google.crypto.tink.AesGcmKey"));
}

TEST(KeyManagerImplTest, GetPrimitiveCallsValidate) {
  ExampleKeyTypeManager internal_km;
  std::unique_ptr<KeyManager<Aead>> key_manager =
      MakeKeyManager<Aead>(&internal_km);

  AesGcmKeyFormat key_format;
  key_format.set_key_size(16);
  auto key_data = *key_manager->get_key_factory()
                       .NewKeyData(key_format.SerializeAsString())
                       .ValueOrDie();

  AesGcmKey key;
  key.ParseFromString(key_data.value());

  EXPECT_CALL(internal_km, ValidateKey(_))
      .WillOnce(Return(util::Status(absl::StatusCode::kOutOfRange,
                                    "GetPrimitiveCallsValidate")));
  EXPECT_THAT(key_manager->GetPrimitive(key_data).status(),
              StatusIs(absl::StatusCode::kOutOfRange,
                       HasSubstr("GetPrimitiveCallsValidate")));
}

TEST(KeyManagerImplTest, GetPrimitiveFromKeyCallsValidate) {
  ExampleKeyTypeManager internal_km;
  std::unique_ptr<KeyManager<Aead>> key_manager =
      MakeKeyManager<Aead>(&internal_km);

  AesGcmKeyFormat key_format;
  key_format.set_key_size(16);
  auto key_data = *key_manager->get_key_factory()
                       .NewKeyData(key_format.SerializeAsString())
                       .ValueOrDie();

  AesGcmKey key;
  key.ParseFromString(key_data.value());

  EXPECT_CALL(internal_km, ValidateKey(_))
      .WillOnce(Return(util::Status(absl::StatusCode::kOutOfRange,
                                    "GetPrimitiveFromKeyCallsValidate")));
  EXPECT_THAT(key_manager->GetPrimitive(key).status(),
              StatusIs(absl::StatusCode::kOutOfRange,
                       HasSubstr("GetPrimitiveFromKeyCallsValidate")));
}

// If we create a KeyManager for a not supported class, creating the key manager
// succeeds, but "GetPrimitive" will fail. Since MakeKeyManager is only supposed
// to be used internally, we are not doing extra work to make this a compile
// time error.
class NotSupported {};
TEST(KeyManagerImplTest, GetPrimitiveFails) {
  ExampleKeyTypeManager internal_km;
  std::unique_ptr<KeyManager<NotSupported>> key_manager =
      MakeKeyManager<NotSupported>(&internal_km);
  AesGcmKeyFormat key_format;
  key_format.set_key_size(16);
  auto key_data = *key_manager->get_key_factory()
                       .NewKeyData(key_format.SerializeAsString())
                       .ValueOrDie();

  EXPECT_THAT(key_manager->GetPrimitive(key_data).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("No PrimitiveFactory was registered")));
}

// Next, we test some of the methods with a KeyTypeManager which has no
// factory.
class ExampleKeyTypeManagerWithoutFactory
    : public KeyTypeManager<AesGcmKey, void, List<Aead, AeadVariant>> {
 public:
  class AeadFactory : public PrimitiveFactory<Aead> {
   public:
    crypto::tink::util::StatusOr<std::unique_ptr<Aead>> Create(
        const AesGcmKey& key) const override {
      // Ignore the key and returned one with a fixed size for this test.
      return {subtle::AesGcmBoringSsl::New(
          util::SecretDataFromStringView(key.key_value()))};
    }
  };

  class AeadVariantFactory : public PrimitiveFactory<AeadVariant> {
   public:
    crypto::tink::util::StatusOr<std::unique_ptr<AeadVariant>> Create(
        const AesGcmKey& key) const override {
      return absl::make_unique<AeadVariant>(key.key_value());
    }
  };

  ExampleKeyTypeManagerWithoutFactory()
      : KeyTypeManager(absl::make_unique<AeadFactory>(),
                       absl::make_unique<AeadVariantFactory>()) {}

  google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const override {
    return google::crypto::tink::KeyData::SYMMETRIC;
  }

  uint32_t get_version() const override { return kVersion; }

  const std::string& get_key_type() const override { return key_type_; }

  util::Status ValidateKey(const AesGcmKey& key) const override {
    util::Status status = ValidateVersion(key.version(), kVersion);
    if (!status.ok()) return status;
    return ValidateAesKeySize(key.key_value().size());
  }

 private:
  static constexpr int kVersion = 0;
  const std::string key_type_ =
      "type.googleapis.com/google.crypto.tink.AesGcmKey";
};

TEST(KeyManagerImplTest, GetPrimitiveWithoutFactoryAead) {
  ExampleKeyTypeManagerWithoutFactory internal_km;
  std::unique_ptr<KeyManager<Aead>> key_manager =
      MakeKeyManager<Aead>(&internal_km);

  AesGcmKeyFormat key_format;
  key_format.set_key_size(16);

  KeyData key_data = test::AsKeyData(
      ExampleKeyTypeManager().CreateKey(key_format).ValueOrDie(),
      KeyData::SYMMETRIC);

  auto aead = key_manager->GetPrimitive(key_data).ValueOrDie();
  std::string encryption = aead->Encrypt("Hi", "aad").ValueOrDie();
  std::string decryption = aead->Decrypt(encryption, "aad").ValueOrDie();
  EXPECT_THAT(decryption, Eq("Hi"));
}

TEST(KeyManagerImplTest, NonexistentFactoryNewKeyFromMessage) {
  ExampleKeyTypeManagerWithoutFactory internal_km;
  std::unique_ptr<KeyManager<AeadVariant>> key_manager =
      MakeKeyManager<AeadVariant>(&internal_km);

  AesGcmKeyFormat key_format;
  key_format.set_key_size(16);
  EXPECT_THAT(key_manager->get_key_factory().NewKey(key_format).status(),
              StatusIs(absl::StatusCode::kUnimplemented));
}

TEST(KeyManagerImplTest, NonexistentFactoryNewKeyFromStringView) {
  ExampleKeyTypeManagerWithoutFactory internal_km;
  std::unique_ptr<KeyManager<AeadVariant>> key_manager =
      MakeKeyManager<AeadVariant>(&internal_km);

  AesGcmKeyFormat key_format;
  key_format.set_key_size(16);

  EXPECT_THAT(key_manager->get_key_factory()
                  .NewKey(key_format.SerializeAsString())
                  .status(),
              StatusIs(absl::StatusCode::kUnimplemented));
}

TEST(KeyManagerImplTest, NonexistentFactoryNewKeyFromKeyData) {
  ExampleKeyTypeManagerWithoutFactory internal_km;
  std::unique_ptr<KeyManager<AeadVariant>> key_manager =
      MakeKeyManager<AeadVariant>(&internal_km);

  AesGcmKeyFormat key_format;
  key_format.set_key_size(16);
  EXPECT_THAT(key_manager->get_key_factory()
                  .NewKeyData(key_format.SerializeAsString())
                  .status(),
              StatusIs(absl::StatusCode::kUnimplemented));
}

TEST(CreateDeriverFunctionForTest, DeriverWithoutFactory) {
  ExampleKeyTypeManagerWithoutFactory internal_km;
  auto deriver = CreateDeriverFunctionFor(&internal_km);
  EXPECT_THAT(deriver("", nullptr).status(),
              StatusIs(absl::StatusCode::kUnimplemented));
}


}  // namespace

}  // namespace internal
}  // namespace tink
}  // namespace crypto
