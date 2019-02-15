// Copyright 2019 Google Inc.
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

#include "tink/signature/ed25519_verify_key_manager.h"

#include "gtest/gtest.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/registry.h"
#include "tink/signature/ed25519_sign_key_manager.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"
#include "proto/aes_eax.pb.h"
#include "proto/common.pb.h"
#include "proto/ed25519.pb.h"
#include "proto/empty.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using google::crypto::tink::AesEaxKey;
using google::crypto::tink::Ed25519PrivateKey;
using google::crypto::tink::Ed25519PublicKey;
using google::crypto::tink::Empty;
using google::crypto::tink::KeyData;

namespace {

class Ed25519VerifyKeyManagerTest : public ::testing::Test {
 protected:
  std::string key_type_prefix_ = "type.googleapis.com/";
  std::string ed25519_verify_key_type_ =
      "type.googleapis.com/google.crypto.tink.Ed25519PublicKey";
};

TEST_F(Ed25519VerifyKeyManagerTest, testBasic) {
  Ed25519VerifyKeyManager key_manager;

  EXPECT_EQ(0, key_manager.get_version());
  EXPECT_EQ("type.googleapis.com/google.crypto.tink.Ed25519PublicKey",
            key_manager.get_key_type());
  EXPECT_TRUE(key_manager.DoesSupport(key_manager.get_key_type()));
}

TEST_F(Ed25519VerifyKeyManagerTest, testKeyDataErrors) {
  Ed25519VerifyKeyManager key_manager;

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
    key_data.set_type_url(ed25519_verify_key_type_);
    key_data.set_value("some bad serialized proto");
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not parse",
                        result.status().error_message());
  }

  {  // Bad version.
    KeyData key_data;
    Ed25519PublicKey key;
    key.set_version(1);
    key_data.set_type_url(ed25519_verify_key_type_);
    key_data.set_value(key.SerializeAsString());
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "version",
                        result.status().error_message());
  }
}

TEST_F(Ed25519VerifyKeyManagerTest, testKeyMessageErrors) {
  Ed25519VerifyKeyManager key_manager;

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
}

TEST_F(Ed25519VerifyKeyManagerTest, testPrimitives) {
  std::string message = "some message to sign";
  Ed25519SignKeyManager sign_key_manager;
  Ed25519VerifyKeyManager verify_key_manager;
  Ed25519PrivateKey private_key = test::GetEd25519TestPrivateKey();
  Ed25519PublicKey key = private_key.public_key();
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
    key_data.set_type_url(ed25519_verify_key_type_);
    key_data.set_value(key.SerializeAsString());
    auto result = verify_key_manager.GetPrimitive(key_data);
    EXPECT_TRUE(result.ok()) << result.status();
    auto verify = std::move(result.ValueOrDie());
    auto verify_status = verify->Verify(signature, message);
    EXPECT_TRUE(verify_status.ok()) << verify_status;
  }
}

TEST_F(Ed25519VerifyKeyManagerTest, testNewKey) {
  Ed25519VerifyKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();
  Empty key_format;
  auto result = key_factory.NewKey(key_format);
  EXPECT_FALSE(result.ok());
  EXPECT_PRED_FORMAT2(testing::IsSubstring,
                      "Operation not supported for public keys, please use the "
                      "Ed25519SignKeyManager.",
                      result.status().error_message());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
