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

#include "tink/hybrid/hybrid_encrypt_factory.h"

#include "gtest/gtest.h"
#include "tink/config.h"
#include "tink/crypto_format.h"
#include "tink/hybrid/hybrid_config.h"
#include "tink/hybrid_encrypt.h"
#include "tink/keyset_handle.h"
#include "tink/util/status.h"
#include "tink/util/test_keyset_handle.h"
#include "tink/util/test_util.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

using crypto::tink::TestKeysetHandle;
using crypto::tink::test::AddRawKey;
using crypto::tink::test::AddTinkKey;
using google::crypto::tink::EciesAeadHkdfPublicKey;
using google::crypto::tink::EcPointFormat;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;

namespace crypto {
namespace tink {
namespace {

class HybridEncryptFactoryTest : public ::testing::Test {
};

EciesAeadHkdfPublicKey GetNewEciesPublicKey() {
  auto ecies_key = test::GetEciesAesGcmHkdfTestKey(
      EllipticCurveType::NIST_P256, EcPointFormat::UNCOMPRESSED,
      HashType::SHA256, 32);
  return ecies_key.public_key();
}

TEST_F(HybridEncryptFactoryTest, testBasic) {
  Keyset keyset;
  auto hybrid_encrypt_result = HybridEncryptFactory::GetPrimitive(
      *TestKeysetHandle::GetKeysetHandle(keyset));
  EXPECT_FALSE(hybrid_encrypt_result.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument,
      hybrid_encrypt_result.status().code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "at least one key",
      hybrid_encrypt_result.status().error_message());
}

TEST_F(HybridEncryptFactoryTest, testPrimitive) {
  // Prepare a Keyset.
  Keyset keyset;
  std::string key_type =
      "type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey";

  uint32_t key_id_1 = 1234543;

  AddTinkKey(key_type, key_id_1, GetNewEciesPublicKey(), KeyStatusType::ENABLED,
             KeyData::ASYMMETRIC_PUBLIC, &keyset);

  uint32_t key_id_2 = 726329;
  AddRawKey(key_type, key_id_2, GetNewEciesPublicKey(), KeyStatusType::ENABLED,
            KeyData::ASYMMETRIC_PUBLIC, &keyset);

  uint32_t key_id_3 = 7213743;
  AddTinkKey(key_type, key_id_3, GetNewEciesPublicKey(), KeyStatusType::ENABLED,
             KeyData::ASYMMETRIC_PUBLIC, &keyset);

  keyset.set_primary_key_id(key_id_3);

  // Initialize the registry.
  ASSERT_TRUE(HybridConfig::Register().ok());

  // Create a KeysetHandle and use it with the factory.
  auto hybrid_encrypt_result = HybridEncryptFactory::GetPrimitive(
      *TestKeysetHandle::GetKeysetHandle(keyset));
  EXPECT_TRUE(hybrid_encrypt_result.ok()) << hybrid_encrypt_result.status();
  auto hybrid_encrypt = std::move(hybrid_encrypt_result.ValueOrDie());

  // Test the resulting HybridEncrypt-instance.
  std::string plaintext = "some plaintext";
  std::string context_info = "some context info";

  auto encrypt_result = hybrid_encrypt->Encrypt(plaintext, context_info);
  EXPECT_TRUE(encrypt_result.ok()) << encrypt_result.status();
}

}  // namespace
}  // namespace tink
}  // namespace crypto
