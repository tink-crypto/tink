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

#include "tink/signature/rsa_ssa_pkcs1_verify_key_manager.h"

#include "gtest/gtest.h"
#include "absl/strings/escaping.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"

#include "tink/registry.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"
#include "proto/common.pb.h"
#include "proto/rsa_ssa_pkcs1.pb.h"
#include "proto/tink.pb.h"

namespace pb = google::crypto::tink;

// TODO(quannguyen): add more tests once RsaSsaPkcs1SignKeyManager is available.
namespace crypto {
namespace tink {

using google::crypto::tink::KeyData;
using google::crypto::tink::RsaSsaPkcs1KeyFormat;
using google::crypto::tink::RsaSsaPkcs1PublicKey;

namespace {

// Test vector from
// https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Digital-Signatures
struct NistTestVector {
  std::string n;
  std::string e;
  std::string message;
  std::string signature;
  pb::HashType hash_type;
};

class RsaSsaPkcs1VerifyKeyManagerTest : public ::testing::Test {
 protected:
  const NistTestVector nist_test_vector_{
      absl::HexStringToBytes(
          "c9548608087bed6be0a4623b9d849aa0b4b4b6114ad0a7d82578076ceefe26ce48d1"
          "448e16d69963510e1e5fc658f3cf8f32a489b62d93fec1cdea6e1dde3feba04bb6a0"
          "34518d83fd6138ea999982ab95d6a03517688ab6f8411c4a96b3e79d4141b8f68338"
          "a9baa99f4e2c7845b573981061c5fd29d5fc21833ff1b030b2deb651e51a291168e2"
          "b45ab4202dcd97b891925c75338e0e648d9d9ad325c10884e1fcdccc1c547b4a9c36"
          "aef939e8802b62405d6e3d358ffa88f206b976b87f8b12b827b0ee7823f9d1955f47"
          "f8678f7843b4cd03777e46717060e82bf149b36d4cf3d0bc7e4d0effde51a72f4ced"
          "8e8e5b11bdb135825ff08873e2f776929abb"),
      absl::HexStringToBytes("3c7bf9"),
      absl::HexStringToBytes(
          "bf082fa4b79f32849e8fae692696fc978ccb648c6e278d9bde4338d7b4632e3228b4"
          "77e6a0d2cd14c68d51abdeed7c8c577457ec9fa2eff93cbf03c019d4014e1dfb3115"
          "02d82f9265689e2d19f91b61c17a701c9ef50a69a55aae4cd57e67edc763c3f987ba"
          "3e46a2a6ffb680c3c25df46716e61228c832419e9f43916a4959"),
      absl::HexStringToBytes(
          "621120a71ff2a182dd2997beb2480f54be516b79a4c202d1d6f59270f8e4d4dbd625"
          "ac52fe0e49c5fd69dc0d15fb19ec58c9312a8161a61cb878abcb11399937f28ff080"
          "3877c239ce0b7c4cbc1e23eca22746b071b2716475424c12944660b929b6240aebe8"
          "47fcb94f63d212f3aa538515dc061e9810fdb0adeb374d0f69d24fd52c94e42668a4"
          "8fc0a57819952a40efb732cfa08b3d2b371780aea97be34efb5239994d7ee7c6ab91"
          "34b76711e76813ad5f5c3a5c95399e907650534dbfafec900c21be1308ddff6eda52"
          "5f35e4fb3d275de46250ea1e4b96b60bd125b85f6c52b5419a725cd69b10cefd0901"
          "abe7f9e15940594cf811e34c60f38768244c"),
      pb::HashType::SHA256};

  std::string rsa_ssa_pkcs1_verify_key_type_ =
      "type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey";
};

TEST_F(RsaSsaPkcs1VerifyKeyManagerTest, NistTestVector) {
  RsaSsaPkcs1VerifyKeyManager key_manager;

  EXPECT_EQ(0, key_manager.get_version());
  EXPECT_EQ("type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PublicKey",
            key_manager.get_key_type());
  EXPECT_TRUE(key_manager.DoesSupport(key_manager.get_key_type()));

  // NIST test vector should work.
  RsaSsaPkcs1PublicKey key;
  key.mutable_params()->set_hash_type(nist_test_vector_.hash_type);
  key.set_version(0);
  key.set_n(nist_test_vector_.n);
  key.set_e(nist_test_vector_.e);
  auto result = key_manager.GetPrimitive(key);
  EXPECT_TRUE(result.ok());
  EXPECT_TRUE(
      result.ValueOrDie()
          ->Verify(nist_test_vector_.signature, nist_test_vector_.message)
          .ok());
}

TEST_F(RsaSsaPkcs1VerifyKeyManagerTest, KeyDataErrors) {
  RsaSsaPkcs1VerifyKeyManager key_manager;

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
    key_data.set_type_url(rsa_ssa_pkcs1_verify_key_type_);
    key_data.set_value("some bad serialized proto");
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not parse",
                        result.status().error_message());
  }

  {  // Bad version.
    KeyData key_data;
    RsaSsaPkcs1PublicKey key;
    key.set_version(1);
    key_data.set_type_url(rsa_ssa_pkcs1_verify_key_type_);
    key_data.set_value(key.SerializeAsString());
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "version",
                        result.status().error_message());
  }
}

TEST_F(RsaSsaPkcs1VerifyKeyManagerTest, KeyMessageErrors) {
  RsaSsaPkcs1VerifyKeyManager key_manager;

  {  // Use SHA1 as signature hash.
    RsaSsaPkcs1PublicKey key;
    key.mutable_params()->set_hash_type(pb::HashType::SHA1);
    key.set_version(0);
    key.set_n(nist_test_vector_.n);
    key.set_e(nist_test_vector_.e);
    auto result = key_manager.GetPrimitive(key);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring,
                        "SHA1 is not safe for digital signature",
                        result.status().error_message());
  }

  {  // Small modulus.
    RsaSsaPkcs1PublicKey key;
    key.mutable_params()->set_hash_type(pb::HashType::SHA256);
    key.set_version(0);
    key.set_n("\x23");
    key.set_e("\x3");
    auto result = key_manager.GetPrimitive(key);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring,
                        "only modulus size >= 2048-bit is supported",
                        result.status().error_message());
  }
}

TEST_F(RsaSsaPkcs1VerifyKeyManagerTest, NewKeyError) {
  RsaSsaPkcs1VerifyKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();

  {  // Via NewKey(format_proto).
    RsaSsaPkcs1KeyFormat key_format;
    auto result = key_factory.NewKey(key_format);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::UNIMPLEMENTED, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring,
                        "use the RsaSsaPkcs1SignKeyManager",
                        result.status().error_message());
  }

  {  // Via NewKey(serialized_format_proto).
    RsaSsaPkcs1KeyFormat key_format;
    auto result = key_factory.NewKey(key_format.SerializeAsString());
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::UNIMPLEMENTED, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring,
                        "use the RsaSsaPkcs1SignKeyManager",
                        result.status().error_message());
  }

  {  // Via NewKeyData(serialized_format_proto).
    RsaSsaPkcs1KeyFormat key_format;
    auto result = key_factory.NewKeyData(key_format.SerializeAsString());
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::UNIMPLEMENTED, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring,
                        "use the RsaSsaPkcs1SignKeyManager",
                        result.status().error_message());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
