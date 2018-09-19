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

#include "tink/signature/ecdsa_verify_key_manager.h"

#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/registry.h"
#include "tink/signature/ecdsa_sign_key_manager.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"
#include "gtest/gtest.h"
#include "proto/common.pb.h"
#include "proto/ecdsa.pb.h"
#include "proto/aes_eax.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using google::crypto::tink::AesEaxKey;
using google::crypto::tink::EcdsaKeyFormat;
using google::crypto::tink::EcdsaPrivateKey;
using google::crypto::tink::EcdsaPublicKey;
using google::crypto::tink::EcdsaSignatureEncoding;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyData;

namespace {

class EcdsaVerifyKeyManagerTest : public ::testing::Test {
 protected:
  std::string key_type_prefix_ = "type.googleapis.com/";
  std::string ecdsa_verify_key_type_ =
      "type.googleapis.com/google.crypto.tink.EcdsaPublicKey";
};

TEST_F(EcdsaVerifyKeyManagerTest, testBasic) {
  EcdsaVerifyKeyManager key_manager;

  EXPECT_EQ(0, key_manager.get_version());
  EXPECT_EQ("type.googleapis.com/google.crypto.tink.EcdsaPublicKey",
            key_manager.get_key_type());
  EXPECT_TRUE(key_manager.DoesSupport(key_manager.get_key_type()));
}

TEST_F(EcdsaVerifyKeyManagerTest, testKeyDataErrors) {
  EcdsaVerifyKeyManager key_manager;

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
    key_data.set_type_url(ecdsa_verify_key_type_);
    key_data.set_value("some bad serialized proto");
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not parse",
                        result.status().error_message());
  }

  {  // Bad version.
    KeyData key_data;
    EcdsaPublicKey key;
    key.set_version(1);
    key_data.set_type_url(ecdsa_verify_key_type_);
    key_data.set_value(key.SerializeAsString());
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "version",
                        result.status().error_message());
  }
}

TEST_F(EcdsaVerifyKeyManagerTest, testKeyMessageErrors) {
  EcdsaVerifyKeyManager key_manager;

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

  {  // Bad elliptic curve.
    EcdsaPublicKey key;
    key.mutable_params()->set_encoding(EcdsaSignatureEncoding::DER);
    key.mutable_params()->set_curve(EllipticCurveType::UNKNOWN_CURVE);
    auto result = key_manager.GetPrimitive(key);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "Unsupported elliptic curve",
                        result.status().error_message());
  }

  {  // Bad hash type for NIST P256.
    EcdsaPublicKey key;
    key.mutable_params()->set_encoding(EcdsaSignatureEncoding::DER);
    key.mutable_params()->set_curve(EllipticCurveType::NIST_P256);
    key.mutable_params()->set_hash_type(HashType::SHA512);
    auto result = key_manager.GetPrimitive(key);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "Only SHA256",
                        result.status().error_message());
  }

  {  // Bad hash type for NIST P384.
    EcdsaPublicKey key;
    key.mutable_params()->set_encoding(EcdsaSignatureEncoding::DER);
    key.mutable_params()->set_curve(EllipticCurveType::NIST_P384);
    key.mutable_params()->set_hash_type(HashType::SHA256);
    auto result = key_manager.GetPrimitive(key);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "Only SHA512",
                        result.status().error_message());
  }

  {  // Bad hash type for NIST P521.
    EcdsaPublicKey key;
    key.mutable_params()->set_encoding(EcdsaSignatureEncoding::DER);
    key.mutable_params()->set_curve(EllipticCurveType::NIST_P384);
    key.mutable_params()->set_hash_type(HashType::SHA256);
    auto result = key_manager.GetPrimitive(key);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "Only SHA512",
                        result.status().error_message());
  }
}

TEST_F(EcdsaVerifyKeyManagerTest, testPrimitives) {
  EcdsaSignatureEncoding encodings[2] = {EcdsaSignatureEncoding::DER,
                                         EcdsaSignatureEncoding::IEEE_P1363};
  for (EcdsaSignatureEncoding encoding : encodings) {
    std::string message = "some message to sign";
    EcdsaSignKeyManager sign_key_manager;
    EcdsaVerifyKeyManager verify_key_manager;
    EcdsaPrivateKey private_key = test::GetEcdsaTestPrivateKey(
        EllipticCurveType::NIST_P256, HashType::SHA256, encoding);
    EcdsaPublicKey key = private_key.public_key();
    auto sign =
        std::move(sign_key_manager.GetPrimitive(private_key).ValueOrDie());
    std::string signature = sign->Sign(message).ValueOrDie();

    {  // Using Key proto.
      auto result = verify_key_manager.GetPrimitive(key);
      EXPECT_TRUE(result.ok()) << result.status();
      auto verify = std::move(result.ValueOrDie());
      auto verify_status = verify->Verify(signature, message);
      EXPECT_TRUE(verify_status.ok()) << verify_status;
    }

    {  // Using KeyData proto.
      KeyData key_data;
      key_data.set_type_url(ecdsa_verify_key_type_);
      key_data.set_value(key.SerializeAsString());
      auto result = verify_key_manager.GetPrimitive(key_data);
      EXPECT_TRUE(result.ok()) << result.status();
      auto verify = std::move(result.ValueOrDie());
      auto verify_status = verify->Verify(signature, message);
      EXPECT_TRUE(verify_status.ok()) << verify_status;
    }

    {  // Using Key proto with wrong encoding.
      auto params = key.mutable_params();
      params->set_encoding(encoding == EcdsaSignatureEncoding::DER
                               ? EcdsaSignatureEncoding::IEEE_P1363
                               : EcdsaSignatureEncoding::DER);
      auto result = verify_key_manager.GetPrimitive(key);
      EXPECT_TRUE(result.ok()) << result.status();
      auto verify = std::move(result.ValueOrDie());
      auto verify_status = verify->Verify(signature, message);
      EXPECT_FALSE(verify_status.ok()) << verify_status;
    }
  }
}

TEST_F(EcdsaVerifyKeyManagerTest, testNewKeyError) {
  EcdsaVerifyKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();

  { // Via NewKey(format_proto).
    EcdsaKeyFormat key_format;
    auto result = key_factory.NewKey(key_format);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::UNIMPLEMENTED, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "use the EcdsaSignKeyManager",
                        result.status().error_message());
  }

  { // Via NewKey(serialized_format_proto).
    EcdsaKeyFormat key_format;
    auto result = key_factory.NewKey(key_format.SerializeAsString());
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::UNIMPLEMENTED, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "use the EcdsaSignKeyManager",
                        result.status().error_message());
  }

  { // Via NewKeyData(serialized_format_proto).
    EcdsaKeyFormat key_format;
    auto result = key_factory.NewKeyData(key_format.SerializeAsString());
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::UNIMPLEMENTED, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "use the EcdsaSignKeyManager",
                        result.status().error_message());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
