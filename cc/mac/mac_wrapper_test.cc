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
////////////////////////////////////////////////////////////////////////////////

#include "tink/mac/mac_wrapper.h"
#include "tink/crypto_format.h"
#include "tink/mac.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/test_util.h"
#include "gtest/gtest.h"

using crypto::tink::test::DummyMac;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;
using google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {
namespace {

TEST(MacWrapperTest, WrapNullptr) {
  auto mac_result = MacWrapper().Wrap(nullptr);
  EXPECT_FALSE(mac_result.ok());
  EXPECT_EQ(util::error::INTERNAL, mac_result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "non-NULL",
                      mac_result.status().error_message());
}

TEST(MacWrapperTest, WrapEmpty) {
  std::unique_ptr<PrimitiveSet<Mac>> mac_set(new PrimitiveSet<Mac>());
  auto mac_result = MacWrapper().Wrap(std::move(mac_set));
  EXPECT_FALSE(mac_result.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT, mac_result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "no primary",
                      mac_result.status().error_message());
}

TEST(MacWrapperTest, Basic) {
  Keyset::Key* key;
  Keyset keyset;

  uint32_t key_id_0 = 1234543;
  key = keyset.add_key();
  key->set_output_prefix_type(OutputPrefixType::TINK);
  key->set_key_id(key_id_0);
  key->set_status(KeyStatusType::ENABLED);

  uint32_t key_id_1 = 726329;
  key = keyset.add_key();
  key->set_output_prefix_type(OutputPrefixType::LEGACY);
  key->set_key_id(key_id_1);
  key->set_status(KeyStatusType::ENABLED);

  uint32_t key_id_2 = 7213743;
  key = keyset.add_key();
  key->set_output_prefix_type(OutputPrefixType::TINK);
  key->set_key_id(key_id_2);
  key->set_status(KeyStatusType::ENABLED);

  std::string mac_name_0 = "mac0";
  std::string mac_name_1 = "mac1";
  std::string mac_name_2 = "mac2";
  std::unique_ptr<PrimitiveSet<Mac>> mac_set(new PrimitiveSet<Mac>());
  auto entry_result = mac_set->AddPrimitive(
      absl::make_unique<DummyMac>(mac_name_0), keyset.key(0));
  ASSERT_TRUE(entry_result.ok());
  entry_result = mac_set->AddPrimitive(absl::make_unique<DummyMac>(mac_name_1),
                                       keyset.key(1));
  ASSERT_TRUE(entry_result.ok());
  entry_result = mac_set->AddPrimitive(absl::make_unique<DummyMac>(mac_name_2),
                                       keyset.key(2));
  ASSERT_TRUE(entry_result.ok());
  // The last key is the primary.
  mac_set->set_primary(entry_result.ValueOrDie());

  // Wrap mac_set and test the resulting Mac.
  auto mac_result = MacWrapper().Wrap(std::move(mac_set));
  EXPECT_TRUE(mac_result.ok()) << mac_result.status();
  std::unique_ptr<Mac> mac = std::move(mac_result.ValueOrDie());
  std::string data = "some_data_for_mac";

  auto compute_mac_result = mac->ComputeMac(data);
  EXPECT_TRUE(compute_mac_result.ok()) << compute_mac_result.status();
  std::string mac_value = compute_mac_result.ValueOrDie();
  EXPECT_PRED_FORMAT2(testing::IsSubstring, mac_name_2, mac_value);

  util::Status status = mac->VerifyMac(mac_value, data);
  EXPECT_TRUE(status.ok()) << status;

  status = mac->VerifyMac("some bad mac", data);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT, status.error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "verification failed",
                      status.error_message());
}

TEST(MacWrapperTest, testLegacyAuthentication) {
  // Prepare a set for the wrapper.
  Keyset::Key key;
  uint32_t key_id = 1234543;
  key.set_output_prefix_type(OutputPrefixType::LEGACY);
  key.set_key_id(key_id);
  key.set_status(KeyStatusType::ENABLED);
  std::string mac_name = "SomeLegacyMac";

  std::unique_ptr<PrimitiveSet<Mac>> mac_set(new PrimitiveSet<Mac>());
  std::unique_ptr<Mac> mac(new DummyMac(mac_name));
  auto entry_result = mac_set->AddPrimitive(std::move(mac), key);
  ASSERT_TRUE(entry_result.ok());
  mac_set->set_primary(entry_result.ValueOrDie());

  // Wrap mac_set and test the resulting Mac.
  auto mac_result = MacWrapper().Wrap(std::move(mac_set));
  EXPECT_TRUE(mac_result.ok()) << mac_result.status();
  mac = std::move(mac_result.ValueOrDie());
  std::string data = "Some data to authenticate";

  // Compute and verify MAC via wrapper.
  auto compute_mac_result = mac->ComputeMac(data);
  EXPECT_TRUE(compute_mac_result.ok()) << compute_mac_result.status();
  std::string mac_value = compute_mac_result.ValueOrDie();
  EXPECT_PRED_FORMAT2(testing::IsSubstring, mac_name, mac_value);
  auto status = mac->VerifyMac(mac_value, data);
  EXPECT_TRUE(status.ok()) << status;

  // Try verifying on raw Mac-primitive using original data.
  std::unique_ptr<Mac> raw_mac(new DummyMac(mac_name));  // same as in wrapper
  std::string raw_mac_value = mac_value.substr(CryptoFormat::kNonRawPrefixSize);
  status = raw_mac->VerifyMac(raw_mac_value, data);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT, status.error_code());

  // Verify on raw Mac-primitive using legacy-formatted data.
  std::string legacy_data = data;
  legacy_data.append(1, CryptoFormat::kLegacyStartByte);
  status = raw_mac->VerifyMac(raw_mac_value, legacy_data);
  EXPECT_TRUE(status.ok()) << status;
}

}  // namespace
}  // namespace tink
}  // namespace crypto
