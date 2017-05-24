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

#include "cc/hybrid/hybrid_decrypt_factory.h"

#include "cc/hybrid_decrypt.h"
#include "cc/crypto_format.h"
#include "cc/keyset_handle.h"
#include "cc/util/status.h"
#include "cc/util/test_util.h"
#include "gtest/gtest.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

using crypto::tink::test::AddRawKey;
using crypto::tink::test::AddTinkKey;
using google::crypto::tink::EciesAeadHkdfKeyFormat;
using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;
using google::crypto::tink::KeyTemplate;

namespace crypto {
namespace tink {
namespace {

class HybridDecryptFactoryTest : public ::testing::Test {
 protected:
  void SetUp() override {
  }
  void TearDown() override {
  }
};

TEST_F(HybridDecryptFactoryTest, testBasic) {
  EXPECT_TRUE(HybridDecryptFactory::RegisterStandardKeyTypes().ok());
  EXPECT_TRUE(HybridDecryptFactory::RegisterLegacyKeyTypes().ok());

  Keyset keyset;
  KeysetHandle keyset_handle(keyset);
  auto hybrid_decrypt_result =
      HybridDecryptFactory::GetPrimitive(keyset_handle);
  EXPECT_FALSE(hybrid_decrypt_result.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT,
      hybrid_decrypt_result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "no primary",
      hybrid_decrypt_result.status().error_message());
}

TEST_F(HybridDecryptFactoryTest, testPrimitive) {
  // Prepare a Keyset.
  Keyset keyset;
  Keyset::Key new_key;
  std::string key_type =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey";

  uint32_t key_id_1 = 1234543;
  // TODO(przydatek): init the new_key properly.
  AddTinkKey(key_type, key_id_1, new_key, KeyStatusType::ENABLED,
             KeyData::ASYMMETRIC_PRIVATE, &keyset);

  uint32_t key_id_2 = 726329;
  // TODO(przydatek): init the new_key properly.
  AddRawKey(key_type, key_id_2, new_key, KeyStatusType::ENABLED,
            KeyData::ASYMMETRIC_PRIVATE, &keyset);

  uint32_t key_id_3 = 7213743;
  // TODO(przydatek): init the new_key properly.
  AddTinkKey(key_type, key_id_3, new_key, KeyStatusType::ENABLED,
             KeyData::ASYMMETRIC_PRIVATE, &keyset);

  keyset.set_primary_key_id(key_id_3);

  // Create a KeysetHandle and use it with the factory.
  KeysetHandle keyset_handle(keyset);
  auto hybrid_decrypt_result =
      HybridDecryptFactory::GetPrimitive(keyset_handle);
  EXPECT_TRUE(hybrid_decrypt_result.ok()) << hybrid_decrypt_result.status();
  auto hybrid_decrypt = std::move(hybrid_decrypt_result.ValueOrDie());

  // Test the resulting HybridDecrypt-instance.
  std::string ciphertext = "some ciphertext";
  std::string context_info = "some context info";

  auto decrypt_result = hybrid_decrypt->Decrypt(ciphertext, context_info);
  EXPECT_FALSE(decrypt_result.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT,
      decrypt_result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "decryption failed",
      decrypt_result.status().error_message());
}

}  // namespace
}  // namespace tink
}  // namespace crypto


int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
