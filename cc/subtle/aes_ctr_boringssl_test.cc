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

#include "tink/subtle/aes_ctr_boringssl.h"

#include <string>
#include <vector>

#include "tink/subtle/random.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"
#include "gtest/gtest.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

TEST(AesCtrBoringSslTest, testEncryptDecrypt) {
  std::string key(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  int iv_size = 12;
  auto res = AesCtrBoringSsl::New(key, iv_size);
  EXPECT_TRUE(res.ok()) << res.status();
  auto cipher = std::move(res.ValueOrDie());
  std::string message = "Some data to encrypt.";
  auto ct = cipher->Encrypt(message);
  EXPECT_TRUE(ct.ok()) << ct.status();
  EXPECT_EQ(ct.ValueOrDie().size(), message.size() + iv_size);
  auto pt = cipher->Decrypt(ct.ValueOrDie());
  EXPECT_TRUE(pt.ok()) << pt.status();
  EXPECT_EQ(pt.ValueOrDie(), message);
}

TEST(AesCtrBoringSslTest, testEncryptDecrypt_randomMessage) {
  std::string key(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  int iv_size = 12;
  auto res = AesCtrBoringSsl::New(key, iv_size);
  EXPECT_TRUE(res.ok()) << res.status();
  auto cipher = std::move(res.ValueOrDie());
  for (int i = 0; i < 256; i++) {
    std::string message = Random::GetRandomBytes(i);
    auto ct = cipher->Encrypt(message);
    EXPECT_TRUE(ct.ok()) << ct.status();
    EXPECT_EQ(ct.ValueOrDie().size(), message.size() + iv_size);
    auto pt = cipher->Decrypt(ct.ValueOrDie());
    EXPECT_TRUE(pt.ok()) << pt.status();
    EXPECT_EQ(pt.ValueOrDie(), message);
  }
}

TEST(AesCtrBoringSslTest, testEncryptDecrypt_randomKey_randomMessage) {
  for (int i = 0; i < 256; i++) {
    std::string key(Random::GetRandomBytes(16));
    int iv_size = 12;
    auto res = AesCtrBoringSsl::New(key, iv_size);
    EXPECT_TRUE(res.ok()) << res.status();
    auto cipher = std::move(res.ValueOrDie());
    std::string message = Random::GetRandomBytes(i);
    auto ct = cipher->Encrypt(message);
    EXPECT_TRUE(ct.ok()) << ct.status();
    EXPECT_EQ(ct.ValueOrDie().size(), message.size() + iv_size);
    auto pt = cipher->Decrypt(ct.ValueOrDie());
    EXPECT_TRUE(pt.ok()) << pt.status();
    EXPECT_EQ(pt.ValueOrDie(), message);
  }
}

TEST(AesCtrBoringSslTest, testEncryptDecrypt_invalidIvSize) {
  std::string key(test::HexDecodeOrDie("000102030405060708090a0b0c0d0e0f"));
  int iv_size = 11;
  auto res1 = AesCtrBoringSsl::New(key, iv_size);
  EXPECT_FALSE(res1.ok()) << res1.status();

  iv_size = 17;
  auto res2 = AesCtrBoringSsl::New(key, iv_size);
  EXPECT_FALSE(res2.ok()) << res2.status();
}

TEST(AesCtrBoringSslTest, testNistTestVector) {
  // NIST SP 800-38A pp 55.
  std::string key(test::HexDecodeOrDie("2b7e151628aed2a6abf7158809cf4f3c"));
  std::string ciphertext(test::HexDecodeOrDie(
      "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff874d6191b620e3261bef6864990db6ce"));
  std::string message(test::HexDecodeOrDie("6bc1bee22e409f96e93d7e117393172a"));
  int iv_size = 16;
  auto res = AesCtrBoringSsl::New(key, iv_size);
  EXPECT_TRUE(res.ok()) << res.status();
  auto cipher = std::move(res.ValueOrDie());
  auto pt = cipher->Decrypt(ciphertext);
  EXPECT_TRUE(pt.ok()) << pt.status();
  EXPECT_EQ(pt.ValueOrDie(), message);
}

TEST(AesCtrBoringSslTest, testMultipleEncrypt) {
  std::string key(Random::GetRandomBytes(16));
  int iv_size = 12;
  auto res = AesCtrBoringSsl::New(key, iv_size);
  EXPECT_TRUE(res.ok()) << res.status();
  auto cipher = std::move(res.ValueOrDie());
  std::string message = "Some data to encrypt.";
  auto ct1 = cipher->Encrypt(message);
  auto ct2 = cipher->Encrypt(message);
  EXPECT_NE(ct1.ValueOrDie(), ct2.ValueOrDie());
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
