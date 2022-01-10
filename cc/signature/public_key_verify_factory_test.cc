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

#include "tink/signature/public_key_verify_factory.h"

#include <string>
#include <utility>

#include "gtest/gtest.h"
#include "tink/config.h"
#include "tink/crypto_format.h"
#include "tink/keyset_handle.h"
#include "tink/public_key_verify.h"
#include "tink/registry.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/signature/signature_config.h"
#include "tink/util/status.h"
#include "tink/util/test_keyset_handle.h"
#include "tink/util/test_util.h"
#include "proto/ecdsa.pb.h"
#include "proto/tink.pb.h"

using crypto::tink::TestKeysetHandle;
using crypto::tink::test::AddTinkKey;
using google::crypto::tink::EcdsaPublicKey;
using google::crypto::tink::EcdsaSignatureEncoding;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;

namespace crypto {
namespace tink {
namespace {

class PublicKeyVerifyFactoryTest : public ::testing::Test {
 protected:
  void SetUp() override {
    auto status = SignatureConfig::Register();
    ASSERT_TRUE(status.ok()) << status;
  }
};

EcdsaPublicKey GetNewEcdsaPublicKey() {
  auto ecdsa_key = test::GetEcdsaTestPrivateKey(EllipticCurveType::NIST_P256,
                                                HashType::SHA256,
                                                EcdsaSignatureEncoding::DER);
  return ecdsa_key.public_key();
}

TEST_F(PublicKeyVerifyFactoryTest, testBasic) {
  Keyset keyset;
  auto public_key_verify_result = PublicKeyVerifyFactory::GetPrimitive(
      *TestKeysetHandle::GetKeysetHandle(keyset));
  EXPECT_FALSE(public_key_verify_result.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument,
      public_key_verify_result.status().code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "at least one key",
                      std::string(public_key_verify_result.status().message()));
}

TEST_F(PublicKeyVerifyFactoryTest, testPrimitive) {
  // Prepare a Keyset.
  Keyset keyset;
  std::string key_type =
      "type.googleapis.com/google.crypto.tink.EcdsaPublicKey";

  uint32_t key_id_1 = 1234543;
  AddTinkKey(key_type, key_id_1, GetNewEcdsaPublicKey(),
             KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PUBLIC, &keyset);

  uint32_t key_id_2 = 726329;
  AddTinkKey(key_type, key_id_2, GetNewEcdsaPublicKey(),
             KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PUBLIC, &keyset);

  uint32_t key_id_3 = 7213743;
  AddTinkKey(key_type, key_id_3, GetNewEcdsaPublicKey(),
             KeyStatusType::ENABLED, KeyData::ASYMMETRIC_PUBLIC, &keyset);

  keyset.set_primary_key_id(key_id_3);

  // Create a KeysetHandle and use it with the factory.
  auto public_key_verify_result = PublicKeyVerifyFactory::GetPrimitive(
      *TestKeysetHandle::GetKeysetHandle(keyset));
  EXPECT_TRUE(public_key_verify_result.ok())
      << public_key_verify_result.status();
  auto public_key_verify = std::move(public_key_verify_result.ValueOrDie());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
