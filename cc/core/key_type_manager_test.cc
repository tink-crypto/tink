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

#include "tink/core/key_type_manager.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/aead.h"
#include "tink/subtle/aes_gcm_boringssl.h"
#include "tink/subtle/random.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/validation.h"
#include "proto/aes_gcm.pb.h"

namespace crypto {
namespace tink {

namespace {

using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesGcmKey;
using ::google::crypto::tink::AesGcmKeyFormat;
using ::testing::Eq;

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

  uint32_t get_version() const override { return kVersion; }

  const std::string& get_key_type() const override { return kKeyType; }

  crypto::tink::util::Status ValidateKey(const AesGcmKey& key) const override {
    return util::OkStatus();
  }

  crypto::tink::util::Status ValidateKeyFormat(
      const AesGcmKeyFormat& key_format) const override {
    return util::OkStatus();
  }

  crypto::tink::util::StatusOr<AesGcmKey> CreateKey(
      const AesGcmKeyFormat& key_format) const override {
    AesGcmKey result;
    result.set_key_value(subtle::Random::GetRandomBytes(key_format.key_size()));
    return result;
  }

 private:
  static constexpr int kVersion = 0;
  const std::string kKeyType = "myKeyType";
};

TEST(KeyManagerTest, CreateAead) {
  AesGcmKeyFormat key_format;
  key_format.set_key_size(16);
  AesGcmKey key = ExampleKeyTypeManager().CreateKey(key_format).ValueOrDie();
  std::unique_ptr<Aead> aead =
      ExampleKeyTypeManager().GetPrimitive<Aead>(key).ValueOrDie();

  std::string encryption = aead->Encrypt("Hi", "aad").ValueOrDie();
  std::string decryption = aead->Decrypt(encryption, "aad").ValueOrDie();
  EXPECT_THAT(decryption, Eq("Hi"));
}

TEST(KeyManagerTest, CreateAeadVariant) {
  AesGcmKeyFormat key_format;
  key_format.set_key_size(16);
  AesGcmKey key = ExampleKeyTypeManager().CreateKey(key_format).ValueOrDie();
  std::unique_ptr<AeadVariant> aead_variant =
      ExampleKeyTypeManager().GetPrimitive<AeadVariant>(key).ValueOrDie();
  EXPECT_THAT(aead_variant->get(), Eq(key.key_value()));
}

class NotRegistered {};
TEST(KeyManagerTest, CreateFails) {
  auto failing =
      ExampleKeyTypeManager().GetPrimitive<NotRegistered>(AesGcmKey());
  EXPECT_THAT(failing.status(),
              test::StatusIs(absl::StatusCode::kInvalidArgument));
}

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
  const std::string key_type_ = "bla";
};

TEST(KeyManagerWithoutFactoryTest, CreateAead) {
  AesGcmKeyFormat key_format;
  key_format.set_key_size(16);
  AesGcmKey key = ExampleKeyTypeManager().CreateKey(key_format).ValueOrDie();
  std::unique_ptr<Aead> aead = ExampleKeyTypeManagerWithoutFactory()
                                   .GetPrimitive<Aead>(key)
                                   .ValueOrDie();

  std::string encryption = aead->Encrypt("Hi", "aad").ValueOrDie();
  std::string decryption = aead->Decrypt(encryption, "aad").ValueOrDie();
  EXPECT_THAT(decryption, Eq("Hi"));
}

TEST(KeyManagerWithoutFactoryTest, CreateAeadVariant) {
  AesGcmKeyFormat key_format;
  key_format.set_key_size(16);
  AesGcmKey key = ExampleKeyTypeManager().CreateKey(key_format).ValueOrDie();
  std::unique_ptr<AeadVariant> aead_variant =
      ExampleKeyTypeManager().GetPrimitive<AeadVariant>(key).ValueOrDie();
  EXPECT_THAT(aead_variant->get(), Eq(key.key_value()));
}

TEST(KeyManagerWithoutFactoryTest, CreateFails) {
  auto failing =
      ExampleKeyTypeManagerWithoutFactory().GetPrimitive<NotRegistered>(
          AesGcmKey());
  EXPECT_THAT(failing.status(),
              test::StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace

}  // namespace tink
}  // namespace crypto
