// Copyright 2017 Google Inc.
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

#include "tink/signature/ecdsa_sign_key_manager.h"

#include "tink/public_key_sign.h"
#include "tink/registry.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"
#include "gtest/gtest.h"
#include "proto/common.pb.h"
#include "proto/ecdsa.pb.h"
#include "proto/aes_eax.pb.h"
#include "proto/tink.pb.h"

using google::crypto::tink::AesEaxKey;
using google::crypto::tink::EcdsaKeyFormat;
using google::crypto::tink::EcdsaPrivateKey;
using google::crypto::tink::EcdsaSignatureEncoding;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyData;

namespace crypto {
namespace tink {
namespace {

class EcdsaSignKeyManagerTest : public ::testing::Test {
 protected:
  std::string key_type_prefix_ = "type.googleapis.com/";
  std::string ecdsa_sign_key_type_ =
      "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";
};

TEST_F(EcdsaSignKeyManagerTest, testBasic) {
  EcdsaSignKeyManager key_manager;

  EXPECT_EQ(0, key_manager.get_version());
  EXPECT_EQ("type.googleapis.com/google.crypto.tink.EcdsaPrivateKey",
            key_manager.get_key_type());
  EXPECT_TRUE(key_manager.DoesSupport(key_manager.get_key_type()));
}

TEST_F(EcdsaSignKeyManagerTest, testKeyDataErrors) {
  EcdsaSignKeyManager key_manager;

  {  // Bad key type.
    KeyData key_data;
    std::string bad_key_type =
        "type.googleapis.com/google.crypto.tink.SomeOtherKey";
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
    key_data.set_type_url(ecdsa_sign_key_type_);
    key_data.set_value("some bad serialized proto");
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not parse",
                        result.status().error_message());
  }

  {  // Bad version.
    KeyData key_data;
    EcdsaPrivateKey key;
    key.set_version(1);
    key_data.set_type_url(key_type_prefix_ + key.GetDescriptor()->full_name());
    key_data.set_value(key.SerializeAsString());
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "version",
                        result.status().error_message());
  }
}

TEST_F(EcdsaSignKeyManagerTest, testKeyMessageErrors) {
  EcdsaSignKeyManager key_manager;

  {  // Bad protobuffer.
    AesEaxKey key;
    auto result = key_manager.GetPrimitive(key);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "AesEaxKey",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
  }

  {  // Bad encoding.
    EcdsaPrivateKey key;
    auto public_key = key.mutable_public_key();
    public_key->mutable_params()->set_encoding(
        EcdsaSignatureEncoding::IEEE_P1363);
    auto result = key_manager.GetPrimitive(key);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "Only DER encoding",
                        result.status().error_message());
  }

  {  // Bad elliptic curve.
    EcdsaPrivateKey key;
    auto public_key = key.mutable_public_key();
    public_key->mutable_params()->set_encoding(EcdsaSignatureEncoding::DER);
    public_key->mutable_params()->set_curve(EllipticCurveType::UNKNOWN_CURVE);
    auto result = key_manager.GetPrimitive(key);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "Unsupported elliptic curve",
                        result.status().error_message());
  }

  {  // Bad hash type for NIST P256.
    EcdsaPrivateKey key;
    auto public_key = key.mutable_public_key();
    public_key->mutable_params()->set_encoding(EcdsaSignatureEncoding::DER);
    public_key->mutable_params()->set_curve(EllipticCurveType::NIST_P256);
    public_key->mutable_params()->set_hash_type(HashType::SHA512);
    auto result = key_manager.GetPrimitive(key);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "Only SHA256",
                        result.status().error_message());
  }

  {  // Bad hash type for NIST P384.
    EcdsaPrivateKey key;
    auto public_key = key.mutable_public_key();
    public_key->mutable_params()->set_encoding(EcdsaSignatureEncoding::DER);
    public_key->mutable_params()->set_curve(EllipticCurveType::NIST_P384);
    public_key->mutable_params()->set_hash_type(HashType::SHA256);
    auto result = key_manager.GetPrimitive(key);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "Only SHA512",
                        result.status().error_message());
  }

  {  // Bad hash type for NIST P521.
    EcdsaPrivateKey key;
    auto public_key = key.mutable_public_key();
    public_key->mutable_params()->set_encoding(EcdsaSignatureEncoding::DER);
    public_key->mutable_params()->set_curve(EllipticCurveType::NIST_P384);
    public_key->mutable_params()->set_hash_type(HashType::SHA256);
    auto result = key_manager.GetPrimitive(key);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "Only SHA512",
                        result.status().error_message());
  }
}

TEST_F(EcdsaSignKeyManagerTest, testPrimitives) {
  std::string message = "some message to sign";
  EcdsaSignKeyManager sign_key_manager;
  EcdsaPrivateKey key = test::GetEcdsaTestPrivateKey(
      EllipticCurveType::NIST_P256, HashType::SHA256);

  {  // Using Key proto.
    auto result = sign_key_manager.GetPrimitive(key);
    EXPECT_TRUE(result.ok()) << result.status();
    auto sign = std::move(result.ValueOrDie());
    auto signing_result = sign->Sign(message);
    EXPECT_TRUE(signing_result.ok()) << signing_result.status();
  }

  {  // Using KeyData proto.
    KeyData key_data;
    key_data.set_type_url(key_type_prefix_ + key.GetDescriptor()->full_name());
    key_data.set_value(key.SerializeAsString());
    auto result = sign_key_manager.GetPrimitive(key_data);
    EXPECT_TRUE(result.ok()) << result.status();
    auto sign = std::move(result.ValueOrDie());
    auto signing_result = sign->Sign(message);
    EXPECT_TRUE(signing_result.ok()) << signing_result.status();
  }
}

TEST_F(EcdsaSignKeyManagerTest, testNewKeyError) {
  EcdsaSignKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();

  { // Via NewKey(format_proto).
    EcdsaKeyFormat key_format;
    auto result = key_factory.NewKey(key_format);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::UNIMPLEMENTED, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not implemented yet",
                        result.status().error_message());
  }

  { // Via NewKey(serialized_format_proto).
    EcdsaKeyFormat key_format;
    auto result = key_factory.NewKey(key_format.SerializeAsString());
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::UNIMPLEMENTED, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not implemented yet",
                        result.status().error_message());
  }

  { // Via NewKeyData(serialized_format_proto).
    EcdsaKeyFormat key_format;
    auto result = key_factory.NewKeyData(key_format.SerializeAsString());
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::UNIMPLEMENTED, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not implemented yet",
                        result.status().error_message());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto


int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
