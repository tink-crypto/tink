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

#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"

#include "gtest/gtest.h"
#include "absl/strings/escaping.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"

#include "tink/registry.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"
#include "proto/common.pb.h"
#include "proto/rsa_ssa_pss.pb.h"
#include "proto/tink.pb.h"

namespace pb = google::crypto::tink;

// TODO(quannguyen): add more tests once RsaSsaPssSignKeyManager is available.
namespace crypto {
namespace tink {

using google::crypto::tink::KeyData;
using google::crypto::tink::RsaSsaPssKeyFormat;
using google::crypto::tink::RsaSsaPssPublicKey;

namespace {

class RsaSsaPssVerifyKeyManagerTest : public ::testing::Test {
 protected:
  std::string key_type_prefix_ = "type.googleapis.com/";
  std::string rsa_ssa_pss_verify_key_type_ =
      "type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey";
};

// Test vector from
// https://csrc.nist.gov/Projects/Cryptographic-Algorithm-Validation-Program/Digital-Signatures
struct NistTestVector {
  std::string n;
  std::string e;
  std::string message;
  std::string signature;
  pb::HashType sig_hash;
  pb::HashType mgf1_hash;
  int salt_length;
};

static const NistTestVector nist_test_vector{
    absl::HexStringToBytes(
        "a47d04e7cacdba4ea26eca8a4c6e14563c2ce03b623b768c0d49868a57121301dbf783"
        "d82f4c055e73960e70550187d0af62ac3496f0a3d9103c2eb7919a72752fa7ce8c688d"
        "81e3aee99468887a15288afbb7acb845b7c522b5c64e678fcd3d22feb84b44272700be"
        "527d2b2025a3f83c2383bf6a39cf5b4e48b3cf2f56eef0dfff18555e31037b91524869"
        "4876f3047814415164f2c660881e694b58c28038a032ad25634aad7b39171dee368e3d"
        "59bfb7299e4601d4587e68caaf8db457b75af42fc0cf1ae7caced286d77fac6cedb03a"
        "d94f1433d2c94d08e60bc1fdef0543cd2951e765b38230fdd18de5d2ca627ddc032fe0"
        "5bbd2ff21e2db1c2f94d8b"),
    absl::HexStringToBytes("10e43f"),
    absl::HexStringToBytes(
        "e002377affb04f0fe4598de9d92d31d6c786040d5776976556a2cfc55e54a1dcb3cb1b"
        "126bd6a4bed2a184990ccea773fcc79d246553e6c64f686d21ad4152673cafec22aeb4"
        "0f6a084e8a5b4991f4c64cf8a927effd0fd775e71e8329e41fdd4457b3911173187b4f"
        "09a817d79ea2397fc12dfe3d9c9a0290c8ead31b6690a6"),
    absl::HexStringToBytes(
        "4f9b425c2058460e4ab2f5c96384da2327fd29150f01955a76b4efe956af06dc08779a"
        "374ee4607eab61a93adc5608f4ec36e47f2a0f754e8ff839a8a19b1db1e884ea4cf348"
        "cd455069eb87afd53645b44e28a0a56808f5031da5ba9112768dfbfca44ebe63a0c057"
        "2b731d66122fb71609be1480faa4e4f75e43955159d70f081e2a32fbb19a48b9f162cf"
        "6b2fb445d2d6994bc58910a26b5943477803cdaaa1bd74b0da0a5d053d8b1dc593091d"
        "b5388383c26079f344e2aea600d0e324164b450f7b9b465111b7265f3b1b063089ae7e"
        "2623fc0fda8052cf4bf3379102fbf71d7c98e8258664ceed637d20f95ff0111881e650"
        "ce61f251d9c3a629ef222d"),
    pb::HashType::SHA256,
    pb::HashType::SHA256,
    32};

TEST_F(RsaSsaPssVerifyKeyManagerTest, testBasic) {
  RsaSsaPssVerifyKeyManager key_manager;

  EXPECT_EQ(0, key_manager.get_version());
  EXPECT_EQ("type.googleapis.com/google.crypto.tink.RsaSsaPssPublicKey",
            key_manager.get_key_type());
  EXPECT_TRUE(key_manager.DoesSupport(key_manager.get_key_type()));

  // NIST test vector should work.
  RsaSsaPssPublicKey key;
  key.mutable_params()->set_mgf1_hash(nist_test_vector.mgf1_hash);
  key.mutable_params()->set_sig_hash(nist_test_vector.sig_hash);
  key.mutable_params()->set_salt_length(nist_test_vector.salt_length);
  key.set_version(0);
  key.set_n(nist_test_vector.n);
  key.set_e(nist_test_vector.e);
  auto result = key_manager.GetPrimitive(key);
  EXPECT_TRUE(result.ok());
  EXPECT_TRUE(result.ValueOrDie()
                  ->Verify(nist_test_vector.signature, nist_test_vector.message)
                  .ok());
}

TEST_F(RsaSsaPssVerifyKeyManagerTest, testKeyDataErrors) {
  RsaSsaPssVerifyKeyManager key_manager;

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
    key_data.set_type_url(rsa_ssa_pss_verify_key_type_);
    key_data.set_value("some bad serialized proto");
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not parse",
                        result.status().error_message());
  }

  {  // Bad version.
    KeyData key_data;
    RsaSsaPssPublicKey key;
    key.set_version(1);
    key_data.set_type_url(rsa_ssa_pss_verify_key_type_);
    key_data.set_value(key.SerializeAsString());
    auto result = key_manager.GetPrimitive(key_data);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "version",
                        result.status().error_message());
  }
}

TEST_F(RsaSsaPssVerifyKeyManagerTest, testKeyMessageErrors) {
  RsaSsaPssVerifyKeyManager key_manager;

  {  // Use SHA1 as signature hash.
    RsaSsaPssPublicKey key;
    key.mutable_params()->set_mgf1_hash(pb::HashType::SHA1);
    key.mutable_params()->set_sig_hash(pb::HashType::SHA1);
    key.mutable_params()->set_salt_length(20);
    key.set_version(0);
    key.set_n(nist_test_vector.n);
    key.set_e(nist_test_vector.e);
    auto result = key_manager.GetPrimitive(key);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring,
                        "SHA1 is not safe for digital signature",
                        result.status().error_message());
  }

  {  // Small modulus.
    RsaSsaPssPublicKey key;
    key.mutable_params()->set_mgf1_hash(pb::HashType::SHA256);
    key.mutable_params()->set_sig_hash(pb::HashType::SHA256);
    key.mutable_params()->set_salt_length(32);
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

  {  // MGF1 hash and signature hash mismatch.
    RsaSsaPssPublicKey key;
    key.mutable_params()->set_mgf1_hash(pb::HashType::SHA256);
    key.mutable_params()->set_sig_hash(pb::HashType::SHA512);
    key.mutable_params()->set_salt_length(32);
    key.set_version(0);
    key.set_n(nist_test_vector.n);
    key.set_e(nist_test_vector.e);
    auto result = key_manager.GetPrimitive(key);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring,
                        "is different from signature hash",
                        result.status().error_message());
  }
}

TEST_F(RsaSsaPssVerifyKeyManagerTest, testNewKeyError) {
  RsaSsaPssVerifyKeyManager key_manager;
  const KeyFactory& key_factory = key_manager.get_key_factory();

  {  // Via NewKey(format_proto).
    RsaSsaPssKeyFormat key_format;
    auto result = key_factory.NewKey(key_format);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::UNIMPLEMENTED, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "use the RsaSsaPssSignKeyManager",
                        result.status().error_message());
  }

  {  // Via NewKey(serialized_format_proto).
    RsaSsaPssKeyFormat key_format;
    auto result = key_factory.NewKey(key_format.SerializeAsString());
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::UNIMPLEMENTED, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "use the RsaSsaPssSignKeyManager",
                        result.status().error_message());
  }

  {  // Via NewKeyData(serialized_format_proto).
    RsaSsaPssKeyFormat key_format;
    auto result = key_factory.NewKeyData(key_format.SerializeAsString());
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::UNIMPLEMENTED, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "not supported",
                        result.status().error_message());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "use the RsaSsaPssSignKeyManager",
                        result.status().error_message());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
