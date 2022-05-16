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

#include <string>
#include <utility>

#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "tink/crypto_format.h"
#include "tink/mac.h"
#include "tink/primitive_set.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

using crypto::tink::test::DummyMac;
using ::crypto::tink::test::IsOk;
using google::crypto::tink::KeysetInfo;
using google::crypto::tink::KeyStatusType;
using google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {
namespace {

TEST(MacWrapperTest, WrapNullptr) {
  auto mac_result = MacWrapper().Wrap(nullptr);
  EXPECT_FALSE(mac_result.ok());
  EXPECT_EQ(absl::StatusCode::kInternal, mac_result.status().code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "non-NULL",
                      std::string(mac_result.status().message()));
}

TEST(MacWrapperTest, WrapEmpty) {
  std::unique_ptr<PrimitiveSet<Mac>> mac_set(new PrimitiveSet<Mac>());
  auto mac_result = MacWrapper().Wrap(std::move(mac_set));
  EXPECT_FALSE(mac_result.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, mac_result.status().code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "no primary",
                      std::string(mac_result.status().message()));
}

TEST(MacWrapperTest, Basic) {
  KeysetInfo::KeyInfo* key_info;
  KeysetInfo keyset_info;

  uint32_t key_id_0 = 1234543;
  key_info = keyset_info.add_key_info();
  key_info->set_output_prefix_type(OutputPrefixType::TINK);
  key_info->set_key_id(key_id_0);
  key_info->set_status(KeyStatusType::ENABLED);

  uint32_t key_id_1 = 726329;
  key_info = keyset_info.add_key_info();
  key_info->set_output_prefix_type(OutputPrefixType::LEGACY);
  key_info->set_key_id(key_id_1);
  key_info->set_status(KeyStatusType::ENABLED);

  uint32_t key_id_2 = 7213743;
  key_info = keyset_info.add_key_info();
  key_info->set_output_prefix_type(OutputPrefixType::TINK);
  key_info->set_key_id(key_id_2);
  key_info->set_status(KeyStatusType::ENABLED);

  std::string mac_name_0 = "mac0";
  std::string mac_name_1 = "mac1";
  std::string mac_name_2 = "mac2";
  std::unique_ptr<PrimitiveSet<Mac>> mac_set(new PrimitiveSet<Mac>());
  auto entry_result = mac_set->AddPrimitive(
      absl::make_unique<DummyMac>(mac_name_0), keyset_info.key_info(0));
  ASSERT_TRUE(entry_result.ok());
  entry_result = mac_set->AddPrimitive(absl::make_unique<DummyMac>(mac_name_1),
                                       keyset_info.key_info(1));
  ASSERT_TRUE(entry_result.ok());
  entry_result = mac_set->AddPrimitive(absl::make_unique<DummyMac>(mac_name_2),
                                       keyset_info.key_info(2));
  ASSERT_TRUE(entry_result.ok());
  // The last key is the primary.
  ASSERT_THAT(mac_set->set_primary(entry_result.value()), IsOk());

  // Wrap mac_set and test the resulting Mac.
  auto mac_result = MacWrapper().Wrap(std::move(mac_set));
  EXPECT_TRUE(mac_result.ok()) << mac_result.status();
  std::unique_ptr<Mac> mac = std::move(mac_result.value());
  std::string data = "some_data_for_mac";

  auto compute_mac_result = mac->ComputeMac(data);
  EXPECT_TRUE(compute_mac_result.ok()) << compute_mac_result.status();
  std::string mac_value = compute_mac_result.value();
  EXPECT_PRED_FORMAT2(testing::IsSubstring, mac_name_2, mac_value);

  util::Status status = mac->VerifyMac(mac_value, data);
  EXPECT_TRUE(status.ok()) << status;

  status = mac->VerifyMac("some bad mac", data);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, status.code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "verification failed",
                      std::string(status.message()));
}

TEST(MacWrapperTest, testLegacyAuthentication) {
  // Prepare a set for the wrapper.
  KeysetInfo::KeyInfo key_info;
  uint32_t key_id = 1234543;
  key_info.set_output_prefix_type(OutputPrefixType::LEGACY);
  key_info.set_key_id(key_id);
  key_info.set_status(KeyStatusType::ENABLED);
  std::string mac_name = "SomeLegacyMac";

  std::unique_ptr<PrimitiveSet<Mac>> mac_set(new PrimitiveSet<Mac>());
  std::unique_ptr<Mac> mac(new DummyMac(mac_name));
  auto entry_result = mac_set->AddPrimitive(std::move(mac), key_info);
  ASSERT_TRUE(entry_result.ok());
  ASSERT_THAT(mac_set->set_primary(entry_result.value()), IsOk());

  // Wrap mac_set and test the resulting Mac.
  auto mac_result = MacWrapper().Wrap(std::move(mac_set));
  EXPECT_TRUE(mac_result.ok()) << mac_result.status();
  mac = std::move(mac_result.value());
  std::string data = "Some data to authenticate";

  // Compute and verify MAC via wrapper.
  auto compute_mac_result = mac->ComputeMac(data);
  EXPECT_TRUE(compute_mac_result.ok()) << compute_mac_result.status();
  std::string mac_value = compute_mac_result.value();
  EXPECT_PRED_FORMAT2(testing::IsSubstring, mac_name, mac_value);
  auto status = mac->VerifyMac(mac_value, data);
  EXPECT_TRUE(status.ok()) << status;

  // Try verifying on raw Mac-primitive using original data.
  std::unique_ptr<Mac> raw_mac(new DummyMac(mac_name));  // same as in wrapper
  std::string raw_mac_value = mac_value.substr(CryptoFormat::kNonRawPrefixSize);
  status = raw_mac->VerifyMac(raw_mac_value, data);
  EXPECT_FALSE(status.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, status.code());

  // Verify on raw Mac-primitive using legacy-formatted data.
  std::string legacy_data = data;
  legacy_data.append(1, CryptoFormat::kLegacyStartByte);
  status = raw_mac->VerifyMac(raw_mac_value, legacy_data);
  EXPECT_TRUE(status.ok()) << status;
}

// Produces a mac which starts in the same way as a legacy non-raw signature.
class TryBreakLegacyMac : public Mac {
 public:
  crypto::tink::util::StatusOr<std::string> ComputeMac(
      absl::string_view data) const override {
    return absl::StrCat(std::string("\x00", 1), "\xff\xff\xff\xff", data);
  }

  crypto::tink::util::Status VerifyMac(absl::string_view mac,
                                       absl::string_view data) const override {
    if (mac != ComputeMac(data).value()) {
      return absl::InvalidArgumentError("Wrong mac");
    }
    return util::OkStatus();
  }
};

// Checks that a raw tag can be verified after a legacy tag is verified with
// the same output prefix. (To prevent regression of b/173013224).
TEST(MacWrapperTest, VerifyRawAfterLegacy) {
  std::unique_ptr<PrimitiveSet<Mac>> mac_set(new PrimitiveSet<Mac>());

  KeysetInfo::KeyInfo key_info_0;
  key_info_0.set_output_prefix_type(OutputPrefixType::RAW);
  key_info_0.set_key_id(1234);
  key_info_0.set_status(KeyStatusType::ENABLED);
  ASSERT_THAT(
      mac_set->AddPrimitive(absl::make_unique<TryBreakLegacyMac>(), key_info_0)
          .status(),
      IsOk());

  KeysetInfo::KeyInfo key_info_1;
  key_info_1.set_output_prefix_type(OutputPrefixType::LEGACY);
  key_info_1.set_key_id(0xffffffff);
  key_info_1.set_status(KeyStatusType::ENABLED);

  auto entry1 =
      mac_set->AddPrimitive(absl::make_unique<DummyMac>(""), key_info_1);
  ASSERT_THAT(entry1.status(), IsOk());
  ASSERT_THAT(mac_set->set_primary(entry1.value()), IsOk());

  // Wrap mac_set and test the resulting Mac.
  auto wrapped_mac = MacWrapper().Wrap(std::move(mac_set));
  EXPECT_THAT(wrapped_mac.status(), IsOk());

  std::string data = "some data";
  std::string mac_tag = TryBreakLegacyMac().ComputeMac(data).value();
  EXPECT_THAT(wrapped_mac.value()->VerifyMac(mac_tag, data), IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
