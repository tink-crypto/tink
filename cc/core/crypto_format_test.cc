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

#include "tink/crypto_format.h"

#include "gtest/gtest.h"
#include "proto/tink.pb.h"

using google::crypto::tink::KeysetInfo;
using google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {
namespace {

// static

void TestNonRawPrefix(const KeysetInfo::KeyInfo& key_info, int prefix_size,
                      uint8_t prefix_first_byte) {
  auto prefix_result =
      CryptoFormat::GetOutputPrefix(key_info);
  EXPECT_TRUE(prefix_result.ok()) << prefix_result.status();
  auto prefix = prefix_result.value();
  EXPECT_EQ(prefix_size, prefix.length());
  EXPECT_EQ(prefix_first_byte, prefix[0]);
  // key_id should follow in BigEndian order
  for (int i = 1; i <= 4; i++) {
    EXPECT_EQ(0xff & (key_info.key_id() >> ((4 - i) * 8)), 0xff & prefix[i])
        << "Failed at byte " << i << ".";
  }
}

class CryptoFormatTest : public ::testing::Test {
};

TEST_F(CryptoFormatTest, testConstants) {
  EXPECT_EQ(5, CryptoFormat::kNonRawPrefixSize);
  EXPECT_EQ(0, CryptoFormat::kRawPrefixSize);
  EXPECT_EQ(0x01, CryptoFormat::kTinkStartByte);
  EXPECT_EQ(0x00, CryptoFormat::kLegacyStartByte);
  EXPECT_EQ("", CryptoFormat::kRawPrefix);
}

TEST_F(CryptoFormatTest, testTinkPrefix) {
  uint32_t key_id = 263829;
  KeysetInfo::KeyInfo key_info;
  key_info.set_output_prefix_type(OutputPrefixType::TINK);
  key_info.set_key_id(key_id);

  TestNonRawPrefix(key_info, CryptoFormat::kNonRawPrefixSize,
                   CryptoFormat::kTinkStartByte);
}

TEST_F(CryptoFormatTest, testLegacyPrefix) {
  uint32_t key_id = 8327256;
  KeysetInfo::KeyInfo key_info;
  key_info.set_output_prefix_type(OutputPrefixType::LEGACY);
  key_info.set_key_id(key_id);

  TestNonRawPrefix(key_info, CryptoFormat::kNonRawPrefixSize,
                   CryptoFormat::kLegacyStartByte);
}

TEST_F(CryptoFormatTest, testCrunchyPrefix) {
  uint32_t key_id = 1223345;
  KeysetInfo::KeyInfo key_info;
  key_info.set_output_prefix_type(OutputPrefixType::CRUNCHY);
  key_info.set_key_id(key_id);

  TestNonRawPrefix(key_info, CryptoFormat::kNonRawPrefixSize,
                   CryptoFormat::kLegacyStartByte);
}

TEST_F(CryptoFormatTest, testRawPrefix) {
  uint32_t key_id = 7662387;
  KeysetInfo::KeyInfo key_info;
  key_info.set_output_prefix_type(OutputPrefixType::RAW);
  key_info.set_key_id(key_id);
  auto prefix_result =
      CryptoFormat::GetOutputPrefix(key_info);
  EXPECT_TRUE(prefix_result.ok()) << prefix_result.status();
  auto prefix = prefix_result.value();
  EXPECT_EQ(CryptoFormat::kRawPrefixSize, prefix.length());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
