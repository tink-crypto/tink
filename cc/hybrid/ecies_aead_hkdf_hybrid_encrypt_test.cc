// Copyright 2017 Google Inc.
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

#include "cc/hybrid/ecies_aead_hkdf_hybrid_encrypt.h"

#include "cc/hybrid_encrypt.h"
#include "cc/util/statusor.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "gtest/gtest.h"

using google::crypto::tink::EciesAeadHkdfPublicKey;
using util::Status;
using util::StatusOr;

namespace crypto {
namespace tink {
namespace {

class EciesAeadHkdfHybridEncryptTest : public ::testing::Test {
 protected:
  void SetUp() override {
  }
  void TearDown() override {
  }
};

TEST_F(EciesAeadHkdfHybridEncryptTest, testBasic) {
  EciesAeadHkdfPublicKey recipient_key;
  auto result = EciesAeadHkdfHybridEncrypt::New(recipient_key);
  EXPECT_TRUE(result.ok()) << result.status();

  std::string plaintext = "some plaintext";
  std::string context_info = "some context info";
  auto hybrid_encrypt = std::move(result.ValueOrDie());
  auto encrypt_result = hybrid_encrypt->Encrypt(plaintext, context_info);
  EXPECT_FALSE(encrypt_result.ok());
  EXPECT_EQ(util::error::UNIMPLEMENTED, encrypt_result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "not implemented",
                      encrypt_result.status().error_message());
}

}  // namespace
}  // namespace tink
}  // namespace crypto

int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
