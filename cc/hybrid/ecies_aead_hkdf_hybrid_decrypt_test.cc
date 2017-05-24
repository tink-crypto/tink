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

#include "cc/hybrid/ecies_aead_hkdf_hybrid_decrypt.h"

#include "cc/hybrid_decrypt.h"
#include "cc/util/statusor.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "gtest/gtest.h"

using google::crypto::tink::EciesAeadHkdfPrivateKey;
using util::Status;
using util::StatusOr;

namespace crypto {
namespace tink {
namespace {

class EciesAeadHkdfHybridDecryptTest : public ::testing::Test {
 protected:
  void SetUp() override {
  }
  void TearDown() override {
  }
};

TEST_F(EciesAeadHkdfHybridDecryptTest, testBasic) {
  EciesAeadHkdfPrivateKey recipient_key;
  auto result = EciesAeadHkdfHybridDecrypt::New(recipient_key);
  EXPECT_TRUE(result.ok()) << result.status();

  std::string ciphertext = "some ciphertext";
  std::string context_info = "some context info";
  auto hybrid_decrypt = std::move(result.ValueOrDie());
  auto decrypt_result = hybrid_decrypt->Decrypt(ciphertext, context_info);
  EXPECT_FALSE(decrypt_result.ok());
  EXPECT_EQ(util::error::UNIMPLEMENTED, decrypt_result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "not implemented",
                      decrypt_result.status().error_message());
}

}  // namespace
}  // namespace tink
}  // namespace crypto

int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
