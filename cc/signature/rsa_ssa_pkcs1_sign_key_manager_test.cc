// Copyright 2018 Google Inc.
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

#include "tink/signature/rsa_ssa_pkcs1_sign_key_manager.h"

#include "gtest/gtest.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/public_key_sign.h"
#include "tink/registry.h"
#include "tink/signature/rsa_ssa_pkcs1_verify_key_manager.h"
#include "tink/signature/signature_key_templates.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"
#include "proto/aes_eax.pb.h"
#include "proto/common.pb.h"
#include "proto/rsa_ssa_pkcs1.pb.h"
#include "proto/tink.pb.h"

namespace pb = google::crypto::tink;

namespace crypto {
namespace tink {

using google::crypto::tink::AesEaxKeyFormat;
using google::crypto::tink::KeyData;
using google::crypto::tink::RsaSsaPkcs1KeyFormat;
using google::crypto::tink::RsaSsaPkcs1PrivateKey;
using google::crypto::tink::RsaSsaPkcs1PublicKey;
using subtle::SubtleUtilBoringSSL;

namespace {

class RsaSsaPkcs1SignKeyManagerTest : public ::testing::Test {
 protected:
  std::string key_type_prefix_ = "type.googleapis.com/";
  std::string rsa_ssa_pkcs1_sign_key_type_ =
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey";
};

// Checks whether given key is compatible with the given format.
void CheckNewKey(const RsaSsaPkcs1PrivateKey& private_key,
                 const RsaSsaPkcs1KeyFormat& key_format) {
  RsaSsaPkcs1SignKeyManager key_manager;
  RsaSsaPkcs1PublicKey public_key = private_key.public_key();
  EXPECT_EQ(0, private_key.version());
  EXPECT_TRUE(private_key.has_public_key());
  EXPECT_EQ(0, public_key.version());
  EXPECT_GT(public_key.n().length(), 0);
  EXPECT_GT(public_key.e().length(), 0);
  EXPECT_EQ(public_key.params().SerializeAsString(),
            key_format.params().SerializeAsString());
  EXPECT_EQ(key_format.public_exponent(), public_key.e());
  auto primitive_result = key_manager.GetPrimitive(private_key);
  EXPECT_TRUE(primitive_result.ok()) << primitive_result.status();
  auto n = std::move(SubtleUtilBoringSSL::str2bn(public_key.n()).ValueOrDie());
  auto d = std::move(SubtleUtilBoringSSL::str2bn(private_key.d()).ValueOrDie());
  auto p = std::move(SubtleUtilBoringSSL::str2bn(private_key.p()).ValueOrDie());
  auto q = std::move(SubtleUtilBoringSSL::str2bn(private_key.q()).ValueOrDie());
  auto dp =
      std::move(SubtleUtilBoringSSL::str2bn(private_key.dp()).ValueOrDie());
  auto dq =
      std::move(SubtleUtilBoringSSL::str2bn(private_key.dq()).ValueOrDie());
  bssl::UniquePtr<BN_CTX> ctx(BN_CTX_new());

  // Check n = p * q.
  auto n_calc = bssl::UniquePtr<BIGNUM>(BN_new());
  ASSERT_TRUE(BN_mul(n_calc.get(), p.get(), q.get(), ctx.get()));
  ASSERT_TRUE(BN_equal_consttime(n_calc.get(), n.get()));

  // Check n size >= modulus_size_in_bits bit.
  EXPECT_GE(BN_num_bits(n.get()), key_format.modulus_size_in_bits());

  // dp = d mod (p - 1)
  auto pm1 = bssl::UniquePtr<BIGNUM>(BN_dup(p.get()));
  ASSERT_TRUE(BN_sub_word(pm1.get(), 1));
  auto dp_calc = bssl::UniquePtr<BIGNUM>(BN_new());
  ASSERT_TRUE(BN_mod(dp_calc.get(), d.get(), pm1.get(), ctx.get()));
  ASSERT_TRUE(BN_equal_consttime(dp_calc.get(), dp.get()));

  // dq = d mod (q - 1)
  auto qm1 = bssl::UniquePtr<BIGNUM>(BN_dup(q.get()));
  ASSERT_TRUE(BN_sub_word(qm1.get(), 1));
  auto dq_calc = bssl::UniquePtr<BIGNUM>(BN_new());
  ASSERT_TRUE(BN_mod(dq_calc.get(), d.get(), qm1.get(), ctx.get()));

  ASSERT_TRUE(BN_equal_consttime(dq_calc.get(), dq.get()));
}

TEST_F(RsaSsaPkcs1SignKeyManagerTest, Basic) {
  RsaSsaPkcs1SignKeyManager key_manager;
  EXPECT_EQ(0, key_manager.get_version());
  EXPECT_EQ("type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey",
            key_manager.get_key_type());
  EXPECT_TRUE(key_manager.DoesSupport(key_manager.get_key_type()));
}

TEST_F(RsaSsaPkcs1SignKeyManagerTest, NewKeyFromKeyFormat) {
  RsaSsaPkcs1SignKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();
  RsaSsaPkcs1KeyFormat key_format;
  ASSERT_TRUE(key_format.ParseFromString(
      SignatureKeyTemplates::RsaSsaPkcs13072Sha256F4().value()));
  auto result = key_factory.NewKey(key_format);
  EXPECT_TRUE(result.ok()) << result.status();
  auto key = std::move(result.ValueOrDie());
  ASSERT_EQ(rsa_ssa_pkcs1_sign_key_type_,
            key_type_prefix_ + key->GetTypeName());
  std::unique_ptr<RsaSsaPkcs1PrivateKey> rsa_key(
      static_cast<RsaSsaPkcs1PrivateKey*>(key.release()));
  CheckNewKey(*rsa_key, key_format);
}

TEST_F(RsaSsaPkcs1SignKeyManagerTest, NewKeyFromSerializedKeyFormat) {
  RsaSsaPkcs1SignKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();
  RsaSsaPkcs1KeyFormat key_format;
  ASSERT_TRUE(key_format.ParseFromString(
      SignatureKeyTemplates::RsaSsaPkcs14096Sha512F4().value()));
  auto result = key_factory.NewKey(key_format.SerializeAsString());
  EXPECT_TRUE(result.ok()) << result.status();
  auto key = std::move(result.ValueOrDie());
  ASSERT_EQ(rsa_ssa_pkcs1_sign_key_type_,
            key_type_prefix_ + key->GetTypeName());
  std::unique_ptr<RsaSsaPkcs1PrivateKey> rsa_key(
      static_cast<RsaSsaPkcs1PrivateKey*>(key.release()));
  CheckNewKey(*rsa_key, key_format);
}

TEST_F(RsaSsaPkcs1SignKeyManagerTest, NewKeyDataFromSerializedKeyFormat) {
  RsaSsaPkcs1SignKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();
  RsaSsaPkcs1KeyFormat key_format;
  ASSERT_TRUE(key_format.ParseFromString(
      SignatureKeyTemplates::RsaSsaPkcs14096Sha512F4().value()));
  auto result = key_factory.NewKeyData(key_format.SerializeAsString());
  EXPECT_TRUE(result.ok()) << result.status();
  auto key_data = std::move(result.ValueOrDie());
  ASSERT_EQ(rsa_ssa_pkcs1_sign_key_type_, key_data->type_url());
  RsaSsaPkcs1PrivateKey rsa_key;
  ASSERT_TRUE(rsa_key.ParseFromString(key_data->value()));
  CheckNewKey(rsa_key, key_format);
}

TEST_F(RsaSsaPkcs1SignKeyManagerTest, PublicKeyExtraction) {
  RsaSsaPkcs1SignKeyManager sign_key_manager;
  auto private_key_factory = dynamic_cast<const PrivateKeyFactory*>(
      &(sign_key_manager.get_key_factory()));
  ASSERT_NE(private_key_factory, nullptr);
  auto new_key_result = private_key_factory->NewKey(
      SignatureKeyTemplates::RsaSsaPkcs13072Sha256F4().value());
  std::unique_ptr<RsaSsaPkcs1PrivateKey> private_key(
      static_cast<RsaSsaPkcs1PrivateKey*>(
          new_key_result.ValueOrDie().release()));
  auto public_key_data_result =
      private_key_factory->GetPublicKeyData(private_key->SerializeAsString());
  EXPECT_TRUE(public_key_data_result.ok()) << public_key_data_result.status();
  auto public_key_data = std::move(public_key_data_result.ValueOrDie());
  EXPECT_EQ(RsaSsaPkcs1VerifyKeyManager::static_key_type(),
            public_key_data->type_url());
  EXPECT_EQ(KeyData::ASYMMETRIC_PUBLIC, public_key_data->key_material_type());
  EXPECT_EQ(private_key->public_key().SerializeAsString(),
            public_key_data->value());
  // Sign with private key and verify with public key.
  RsaSsaPkcs1VerifyKeyManager verify_key_manager;
  auto signer = sign_key_manager.GetPrimitive(*private_key);
  auto verifier = verify_key_manager.GetPrimitive(*public_key_data);
  std::string message = "Wycheproof";
  EXPECT_TRUE(
      verifier.ValueOrDie()
          ->Verify(signer.ValueOrDie()->Sign(message).ValueOrDie(), message)
          .ok());
}

TEST_F(RsaSsaPkcs1SignKeyManagerTest, NewKeyWithWeakSignatureHash) {
  RsaSsaPkcs1SignKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();
  RsaSsaPkcs1KeyFormat key_format;
  ASSERT_TRUE(key_format.ParseFromString(
      SignatureKeyTemplates::RsaSsaPkcs14096Sha512F4().value()));
  key_format.mutable_params()->set_hash_type(pb::HashType::SHA1);
  auto result = key_factory.NewKey(key_format.SerializeAsString());
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring,
                      "SHA1 is not safe for digital signature",
                      result.status().error_message());
}

TEST_F(RsaSsaPkcs1SignKeyManagerTest, NewKeyWithSmallModulus) {
  RsaSsaPkcs1SignKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();
  RsaSsaPkcs1KeyFormat key_format;
  ASSERT_TRUE(key_format.ParseFromString(
      SignatureKeyTemplates::RsaSsaPkcs14096Sha512F4().value()));
  key_format.set_modulus_size_in_bits(512);
  auto result = key_factory.NewKey(key_format.SerializeAsString());
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring,
                      "only modulus size >= 2048-bit is supported",
                      result.status().error_message());
}

TEST_F(RsaSsaPkcs1SignKeyManagerTest, GetPrimitiveWithWeakSignatureHash) {
  RsaSsaPkcs1SignKeyManager sign_key_manager;
  auto private_key_factory = dynamic_cast<const PrivateKeyFactory*>(
      &(sign_key_manager.get_key_factory()));
  ASSERT_NE(private_key_factory, nullptr);
  auto new_key_result = private_key_factory->NewKey(
      SignatureKeyTemplates::RsaSsaPkcs13072Sha256F4().value());
  std::unique_ptr<RsaSsaPkcs1PrivateKey> private_key(
      static_cast<RsaSsaPkcs1PrivateKey*>(
          new_key_result.ValueOrDie().release()));
  private_key->mutable_public_key()->mutable_params()->set_hash_type(
      pb::HashType::SHA1);
  auto result = sign_key_manager.GetPrimitive(*private_key);
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring,
                      "SHA1 is not safe for digital signature",
                      result.status().error_message());
}

TEST_F(RsaSsaPkcs1SignKeyManagerTest, GetPrimitiveWithSmallModulus) {
  RsaSsaPkcs1SignKeyManager sign_key_manager;
  auto private_key_factory = dynamic_cast<const PrivateKeyFactory*>(
      &(sign_key_manager.get_key_factory()));
  ASSERT_NE(private_key_factory, nullptr);
  auto new_key_result = private_key_factory->NewKey(
      SignatureKeyTemplates::RsaSsaPkcs13072Sha256F4().value());
  std::unique_ptr<RsaSsaPkcs1PrivateKey> private_key(
      static_cast<RsaSsaPkcs1PrivateKey*>(
          new_key_result.ValueOrDie().release()));
  private_key->mutable_public_key()->set_n("\x23");
  private_key->mutable_public_key()->set_e("\x3");
  auto result = sign_key_manager.GetPrimitive(*private_key);
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring,
                      "only modulus size >= 2048-bit is supported",
                      result.status().error_message());
}

TEST_F(RsaSsaPkcs1SignKeyManagerTest, KeyDataErrors) {
  RsaSsaPkcs1SignKeyManager key_manager;

  {  // Bad key type.
    KeyData key_data;
    std::string bad_key_type = "type.googleapis.com/google.crypto.tink.SomeOtherKey";
    key_data.set_type_url(bad_key_type);
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, bad_key_type,
                        result.status().error_message());
  }

  {  // Bad key value.
    KeyData key_data;
    key_data.set_type_url(rsa_ssa_pkcs1_sign_key_type_);
    key_data.set_value("some bad serialized proto");
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not parse",
                        result.status().error_message());
  }

  {  // Bad version.
    KeyData key_data;
    RsaSsaPkcs1PrivateKey key;
    key.set_version(1);
    key_data.set_type_url(rsa_ssa_pkcs1_sign_key_type_);
    key_data.set_value(key.SerializeAsString());
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "version",
                        result.status().error_message());
  }
}

TEST_F(RsaSsaPkcs1SignKeyManagerTest, NewKeyErrors) {
  RsaSsaPkcs1SignKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();

  // Empty key format.
  RsaSsaPkcs1KeyFormat key_format;
  {
    auto result = key_factory.NewKey(key_format);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
  }

  // Bad serialized format.
  {
    auto result = key_factory.NewKey("some bad serialization");
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
  }

  // Wrong format proto.
  {
    AesEaxKeyFormat wrong_key_format;
    auto result = key_factory.NewKey(wrong_key_format);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
  }
}

TEST_F(RsaSsaPkcs1SignKeyManagerTest, PublicKeyExtractionErrors) {
  RsaSsaPkcs1SignKeyManager key_manager;
  auto private_key_factory =
      dynamic_cast<const PrivateKeyFactory*>(&(key_manager.get_key_factory()));
  ASSERT_NE(private_key_factory, nullptr);

  AesGcmKeyManager aead_key_manager;
  auto aead_private_key_factory = dynamic_cast<const PrivateKeyFactory*>(
      &(aead_key_manager.get_key_factory()));
  ASSERT_EQ(nullptr, aead_private_key_factory);

  auto aead_key_result = aead_key_manager.get_key_factory().NewKey(
      AeadKeyTemplates::Aes128Gcm().value());
  ASSERT_TRUE(aead_key_result.ok()) << aead_key_result.status();
  auto aead_key = std::move(aead_key_result.ValueOrDie());
  auto public_key_data_result =
      private_key_factory->GetPublicKeyData(aead_key->SerializeAsString());
  EXPECT_FALSE(public_key_data_result.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT,
            public_key_data_result.status().error_code());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
