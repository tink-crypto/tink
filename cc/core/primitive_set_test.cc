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

#include "tink/primitive_set.h"

#include <memory>
#include <string>
#include <thread>  // NOLINT(build/c++11)
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/crypto_format.h"
#include "tink/mac.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

using ::crypto::tink::test::DummyMac;
using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::UnorderedElementsAreArray;

namespace crypto {
namespace tink {
namespace {

class PrimitiveSetTest : public ::testing::Test {
};

void add_primitives(PrimitiveSet<Mac>* primitive_set,
                    int key_id_offset,
                    int primitives_count) {
  for (int i = 0; i < primitives_count; i++) {
    int key_id = key_id_offset + i;
    KeysetInfo::KeyInfo key_info;
    key_info.set_output_prefix_type(OutputPrefixType::TINK);
    key_info.set_key_id(key_id);
    key_info.set_status(KeyStatusType::ENABLED);
    std::unique_ptr<Mac> mac(new DummyMac("dummy MAC"));
    auto add_result = primitive_set->AddPrimitive(std::move(mac), key_info);
    EXPECT_TRUE(add_result.ok()) << add_result.status();
  }
}

void access_primitives(PrimitiveSet<Mac>* primitive_set,
                       int key_id_offset,
                       int primitives_count) {
  for (int i = 0; i < primitives_count; i++) {
    int key_id = key_id_offset + i;
    KeysetInfo::KeyInfo key_info;
    key_info.set_output_prefix_type(OutputPrefixType::TINK);
    key_info.set_key_id(key_id);
    key_info.set_status(KeyStatusType::ENABLED);
    std::string prefix = CryptoFormat::GetOutputPrefix(key_info).value();
    auto get_result = primitive_set->get_primitives(prefix);
    EXPECT_TRUE(get_result.ok()) << get_result.status();
    EXPECT_GE(get_result.value()->size(), 1);
  }
}

TEST_F(PrimitiveSetTest, ConcurrentOperations) {
  PrimitiveSet<Mac> mac_set;
  int offset_a = 100;
  int offset_b = 150;
  int count = 100;

  // Add some primitives.
  std::thread add_primitives_a(add_primitives, &mac_set, offset_a, count);
  std::thread add_primitives_b(add_primitives, &mac_set, offset_b, count);
  add_primitives_a.join();
  add_primitives_b.join();

  // Access primitives.
  std::thread access_primitives_a(access_primitives, &mac_set, offset_a, count);
  std::thread access_primitives_b(access_primitives, &mac_set, offset_b, count);
  access_primitives_a.join();
  access_primitives_b.join();

  // Verify the common key ids added by both threads.
  for (int key_id = offset_a; key_id < offset_b + count; key_id++) {
    KeysetInfo::KeyInfo key_info;
    key_info.set_output_prefix_type(OutputPrefixType::TINK);
    key_info.set_key_id(key_id);
    key_info.set_status(KeyStatusType::ENABLED);
    std::string prefix = CryptoFormat::GetOutputPrefix(key_info).value();
    auto get_result = mac_set.get_primitives(prefix);
    EXPECT_TRUE(get_result.ok()) << get_result.status();
    auto macs = get_result.value();
    if (key_id >= offset_b && key_id < offset_a + count) {
      EXPECT_EQ(2, macs->size());  // overlapping key_id range
    } else {
      EXPECT_EQ(1, macs->size());
    }
  }
}

TEST_F(PrimitiveSetTest, Basic) {
  std::string mac_name_1 = "MAC#1";
  std::unique_ptr<Mac> mac_1(new DummyMac(mac_name_1));
  std::string mac_name_2 = "MAC#2";
  std::unique_ptr<Mac> mac_2(new DummyMac(mac_name_2));
  std::string mac_name_3 = "MAC#3";
  std::unique_ptr<Mac> mac_3(new DummyMac(mac_name_3));
  std::string mac_name_4 = "MAC#3";
  std::unique_ptr<Mac> mac_4(new DummyMac(mac_name_4));
  std::string mac_name_5 = "MAC#3";
  std::unique_ptr<Mac> mac_5(new DummyMac(mac_name_5));
  std::string mac_name_6 = "MAC#3";
  std::unique_ptr<Mac> mac_6(new DummyMac(mac_name_6));

  uint32_t key_id_1 = 1234543;
  KeysetInfo::KeyInfo key_1;
  key_1.set_output_prefix_type(OutputPrefixType::TINK);
  key_1.set_key_id(key_id_1);
  key_1.set_status(KeyStatusType::ENABLED);

  uint32_t key_id_2 = 7213743;
  KeysetInfo::KeyInfo key_2;
  key_2.set_output_prefix_type(OutputPrefixType::LEGACY);
  key_2.set_key_id(key_id_2);
  key_2.set_status(KeyStatusType::ENABLED);

  uint32_t key_id_3 = key_id_2;    // same id as key_2
  KeysetInfo::KeyInfo key_3;
  key_3.set_output_prefix_type(OutputPrefixType::TINK);
  key_3.set_key_id(key_id_3);
  key_3.set_status(KeyStatusType::ENABLED);

  uint32_t key_id_4 = 947327;
  KeysetInfo::KeyInfo key_4;
  key_4.set_output_prefix_type(OutputPrefixType::RAW);
  key_4.set_key_id(key_id_4);
  key_4.set_status(KeyStatusType::ENABLED);

  uint32_t key_id_5 = 529472;
  KeysetInfo::KeyInfo key_5;
  key_5.set_output_prefix_type(OutputPrefixType::RAW);
  key_5.set_key_id(key_id_5);
  key_5.set_status(KeyStatusType::ENABLED);

  uint32_t key_id_6 = key_id_1;    // same id as key_1
  KeysetInfo::KeyInfo key_6;
  key_6.set_output_prefix_type(OutputPrefixType::TINK);
  key_6.set_key_id(key_id_6);
  key_6.set_status(KeyStatusType::ENABLED);

  PrimitiveSet<Mac> primitive_set;
  EXPECT_TRUE(primitive_set.get_primary() == nullptr);
  EXPECT_EQ(absl::StatusCode::kNotFound,
            primitive_set.get_raw_primitives().status().code());
  EXPECT_EQ(absl::StatusCode::kNotFound,
            primitive_set.get_primitives("prefix").status().code());

  // Add all the primitives.
  auto add_primitive_result =
      primitive_set.AddPrimitive(std::move(mac_1), key_1);
  EXPECT_TRUE(add_primitive_result.ok()) << add_primitive_result.status();

  add_primitive_result = primitive_set.AddPrimitive(std::move(mac_2), key_2);
  EXPECT_TRUE(add_primitive_result.ok()) << add_primitive_result.status();

  add_primitive_result = primitive_set.AddPrimitive(std::move(mac_3), key_3);
  EXPECT_TRUE(add_primitive_result.ok()) << add_primitive_result.status();
  EXPECT_THAT(primitive_set.set_primary(add_primitive_result.value()), IsOk());

  add_primitive_result = primitive_set.AddPrimitive(std::move(mac_4), key_4);
  EXPECT_TRUE(add_primitive_result.ok()) << add_primitive_result.status();

  add_primitive_result = primitive_set.AddPrimitive(std::move(mac_5), key_5);
  EXPECT_TRUE(add_primitive_result.ok()) << add_primitive_result.status();

  add_primitive_result = primitive_set.AddPrimitive(std::move(mac_6), key_6);
  EXPECT_TRUE(add_primitive_result.ok()) << add_primitive_result.status();

  // Try adding a "consumed" unique_ptr as a primitive.
  add_primitive_result = primitive_set.AddPrimitive(std::move(mac_6), key_6);
  EXPECT_FALSE(add_primitive_result.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument,
            add_primitive_result.status().code());

  std::string data = "some data";

  {  // Check the primary.
    auto primary = primitive_set.get_primary();
    EXPECT_FALSE(primary == nullptr);
    EXPECT_EQ(KeyStatusType::ENABLED, primary->get_status());
    EXPECT_EQ(DummyMac(mac_name_3).ComputeMac(data).value(),
              primary->get_primitive().ComputeMac(data).value());
  }

  {  // Check raw primitives.
    auto& primitives = *(primitive_set.get_raw_primitives().value());
    EXPECT_EQ(2, primitives.size());
    EXPECT_EQ(DummyMac(mac_name_4).ComputeMac(data).value(),
              primitives[0]->get_primitive().ComputeMac(data).value());
    EXPECT_EQ(KeyStatusType::ENABLED, primitives[0]->get_status());
    EXPECT_EQ(key_4.key_id(), primitives[0]->get_key_id());
    EXPECT_EQ(OutputPrefixType::RAW, primitives[0]->get_output_prefix_type());
    EXPECT_EQ(DummyMac(mac_name_5).ComputeMac(data).value(),
              primitives[1]->get_primitive().ComputeMac(data).value());
    EXPECT_EQ(KeyStatusType::ENABLED, primitives[1]->get_status());
    EXPECT_EQ(key_5.key_id(), primitives[1]->get_key_id());
    EXPECT_EQ(OutputPrefixType::RAW, primitives[1]->get_output_prefix_type());
  }

  {  // Check Tink primitives.
    std::string prefix = CryptoFormat::GetOutputPrefix(key_1).value();
    auto& primitives = *(primitive_set.get_primitives(prefix).value());
    EXPECT_EQ(2, primitives.size());
    EXPECT_EQ(DummyMac(mac_name_1).ComputeMac(data).value(),
              primitives[0]->get_primitive().ComputeMac(data).value());
    EXPECT_EQ(KeyStatusType::ENABLED, primitives[0]->get_status());
    EXPECT_EQ(key_1.key_id(), primitives[0]->get_key_id());
    EXPECT_EQ(OutputPrefixType::TINK, primitives[0]->get_output_prefix_type());
    EXPECT_EQ(DummyMac(mac_name_6).ComputeMac(data).value(),
              primitives[1]->get_primitive().ComputeMac(data).value());
    EXPECT_EQ(KeyStatusType::ENABLED, primitives[1]->get_status());
    EXPECT_EQ(key_1.key_id(), primitives[1]->get_key_id());
    EXPECT_EQ(OutputPrefixType::TINK, primitives[1]->get_output_prefix_type());
  }

  {  // Check another Tink primitive.
    std::string prefix = CryptoFormat::GetOutputPrefix(key_3).value();
    auto& primitives = *(primitive_set.get_primitives(prefix).value());
    EXPECT_EQ(1, primitives.size());
    EXPECT_EQ(DummyMac(mac_name_3).ComputeMac(data).value(),
              primitives[0]->get_primitive().ComputeMac(data).value());
    EXPECT_EQ(KeyStatusType::ENABLED, primitives[0]->get_status());
    EXPECT_EQ(key_3.key_id(), primitives[0]->get_key_id());
    EXPECT_EQ(OutputPrefixType::TINK, primitives[0]->get_output_prefix_type());
  }

  {  // Check legacy primitive.
    std::string prefix = CryptoFormat::GetOutputPrefix(key_2).value();
    auto& primitives = *(primitive_set.get_primitives(prefix).value());
    EXPECT_EQ(1, primitives.size());
    EXPECT_EQ(DummyMac(mac_name_2).ComputeMac(data).value(),
              primitives[0]->get_primitive().ComputeMac(data).value());
    EXPECT_EQ(KeyStatusType::ENABLED, primitives[0]->get_status());
    EXPECT_EQ(key_2.key_id(), primitives[0]->get_key_id());
    EXPECT_EQ(OutputPrefixType::LEGACY,
              primitives[0]->get_output_prefix_type());
  }
}

TEST_F(PrimitiveSetTest, PrimaryKeyWithIdCollisions) {
  std::string mac_name_1 = "MAC#1";
  std::string mac_name_2 = "MAC#2";

  uint32_t key_id_1 = 1234543;
  KeysetInfo::KeyInfo key_info_1;
  key_info_1.set_key_id(key_id_1);
  key_info_1.set_status(KeyStatusType::ENABLED);

  uint32_t key_id_2 = key_id_1;    // same id as key_2
  KeysetInfo::KeyInfo key_info_2;
  key_info_2.set_key_id(key_id_2);
  key_info_2.set_status(KeyStatusType::ENABLED);

  {  // Test with RAW-keys.
    std::unique_ptr<Mac> mac_1(new DummyMac(mac_name_1));
    std::unique_ptr<Mac> mac_2(new DummyMac(mac_name_2));
    key_info_1.set_output_prefix_type(OutputPrefixType::RAW);
    key_info_2.set_output_prefix_type(OutputPrefixType::RAW);
    PrimitiveSet<Mac> primitive_set;
    EXPECT_TRUE(primitive_set.get_primary() == nullptr);

    // Add the first primitive, and set it as primary.
    auto add_primitive_result =
        primitive_set.AddPrimitive(std::move(mac_1), key_info_1);
    EXPECT_TRUE(add_primitive_result.ok()) << add_primitive_result.status();
    ASSERT_THAT(primitive_set.set_primary(add_primitive_result.value()),
                IsOk());

    std::string identifier = "";
    const auto& primitives =
        *(primitive_set.get_primitives(identifier).value());
    EXPECT_EQ(1, primitives.size());
    EXPECT_EQ(primitive_set.get_primary(), primitives[0].get());

    //  Adding another primitive should not invalidate the primary.
    add_primitive_result =
        primitive_set.AddPrimitive(std::move(mac_2), key_info_2);
    EXPECT_TRUE(add_primitive_result.ok()) << add_primitive_result.status();
    EXPECT_EQ(2, primitives.size());
    EXPECT_EQ(primitive_set.get_primary(), primitives[0].get());
  }

  {  // Test with TINK-keys.
    std::unique_ptr<Mac> mac_1(new DummyMac(mac_name_1));
    std::unique_ptr<Mac> mac_2(new DummyMac(mac_name_2));
    key_info_1.set_output_prefix_type(OutputPrefixType::TINK);
    key_info_2.set_output_prefix_type(OutputPrefixType::TINK);
    PrimitiveSet<Mac> primitive_set;
    EXPECT_TRUE(primitive_set.get_primary() == nullptr);

    // Add the first primitive, and set it as primary.
    auto add_primitive_result =
        primitive_set.AddPrimitive(std::move(mac_1), key_info_1);
    EXPECT_TRUE(add_primitive_result.ok()) << add_primitive_result.status();
    ASSERT_THAT(primitive_set.set_primary(add_primitive_result.value()),
                IsOk());

    std::string identifier = CryptoFormat::GetOutputPrefix(key_info_1).value();
    const auto& primitives =
        *(primitive_set.get_primitives(identifier).value());
    EXPECT_EQ(1, primitives.size());
    EXPECT_EQ(primitive_set.get_primary(), primitives[0].get());

    //  Adding another primitive should not invalidate the primary.
    add_primitive_result =
        primitive_set.AddPrimitive(std::move(mac_2), key_info_2);
    EXPECT_TRUE(add_primitive_result.ok()) << add_primitive_result.status();
    EXPECT_EQ(2, primitives.size());
    EXPECT_EQ(primitive_set.get_primary(), primitives[0].get());
  }

  {  // Test with LEGACY-keys.
    std::unique_ptr<Mac> mac_1(new DummyMac(mac_name_1));
    std::unique_ptr<Mac> mac_2(new DummyMac(mac_name_2));
    key_info_1.set_output_prefix_type(OutputPrefixType::LEGACY);
    key_info_2.set_output_prefix_type(OutputPrefixType::LEGACY);
    PrimitiveSet<Mac> primitive_set;
    EXPECT_TRUE(primitive_set.get_primary() == nullptr);

    // Add the first primitive, and set it as primary.
    auto add_primitive_result =
        primitive_set.AddPrimitive(std::move(mac_1), key_info_1);
    EXPECT_TRUE(add_primitive_result.ok()) << add_primitive_result.status();
    ASSERT_THAT(primitive_set.set_primary(add_primitive_result.value()),
                IsOk());

    std::string identifier = CryptoFormat::GetOutputPrefix(key_info_1).value();
    const auto& primitives =
        *(primitive_set.get_primitives(identifier).value());
    EXPECT_EQ(1, primitives.size());
    EXPECT_EQ(primitive_set.get_primary(), primitives[0].get());

    //  Adding another primitive should not invalidate the primary.
    add_primitive_result =
        primitive_set.AddPrimitive(std::move(mac_2), key_info_2);
    EXPECT_TRUE(add_primitive_result.ok()) << add_primitive_result.status();
    EXPECT_EQ(2, primitives.size());
    EXPECT_EQ(primitive_set.get_primary(), primitives[0].get());
  }
}

TEST_F(PrimitiveSetTest, DisabledKey) {
  std::string mac_name_1 = "MAC#1";
  std::unique_ptr<Mac> mac_1(new DummyMac(mac_name_1));

  uint32_t key_id_1 = 1234543;
  KeysetInfo::KeyInfo key_info_1;
  key_info_1.set_output_prefix_type(OutputPrefixType::TINK);
  key_info_1.set_key_id(key_id_1);
  key_info_1.set_status(KeyStatusType::DISABLED);

  PrimitiveSet<Mac> primitive_set;
  // Add all the primitives.
  auto add_primitive_result =
      primitive_set.AddPrimitive(std::move(mac_1), key_info_1);
  EXPECT_FALSE(add_primitive_result.ok());
}

KeysetInfo::KeyInfo CreateKey(uint32_t key_id,
                              OutputPrefixType output_prefix_type,
                              KeyStatusType key_status,
                              absl::string_view type_url) {
  KeysetInfo::KeyInfo key_info;
  key_info.set_output_prefix_type(output_prefix_type);
  key_info.set_key_id(key_id);
  key_info.set_status(key_status);
  std::string type_url_str(type_url);
  key_info.set_type_url(type_url_str);
  return key_info;
}

// Struct to hold MAC, Id and type_url.
struct MacIdAndTypeUrl {
  std::string mac;
  std::string id;
  std::string type_url;
};

bool operator==(const MacIdAndTypeUrl& first, const MacIdAndTypeUrl& other) {
  return first.mac == other.mac && first.id == other.id &&
         first.type_url == other.type_url;
}

TEST_F(PrimitiveSetTest, GetAll) {
  PrimitiveSet<Mac> pset;
  EXPECT_THAT(
      pset.AddPrimitive(
              absl::make_unique<DummyMac>("MAC1"),
              CreateKey(0x01010101, OutputPrefixType::TINK,
                        KeyStatusType::ENABLED, /*type_url=*/
                        "type.googleapis.com/google.crypto.tink.HmacKey"))
          .status(),
      IsOk());

  EXPECT_THAT(
      pset.AddPrimitive(
              absl::make_unique<DummyMac>("MAC2"),
              CreateKey(0x02020202, OutputPrefixType::TINK,
                        KeyStatusType::ENABLED, /*type_url=*/
                        "type.googleapis.com/google.crypto.tink.HmacKey"))
          .status(),
      IsOk());
  // Add primitive and make it primary.
  auto entry_or = pset.AddPrimitive(
      absl::make_unique<DummyMac>("MAC3"),
      CreateKey(0x02020202, OutputPrefixType::TINK,
                KeyStatusType::ENABLED, /*type_url=*/
                "type.googleapis.com/google.crypto.tink.AesCmacKey"));
  ASSERT_THAT(entry_or.status(), IsOk());
  EXPECT_THAT(pset.set_primary(entry_or.value()), IsOk());

  EXPECT_THAT(
      pset.AddPrimitive(
              absl::make_unique<DummyMac>("MAC4"),
              CreateKey(0x02020202, OutputPrefixType::RAW,
                        KeyStatusType::ENABLED, /*type_url=*/
                        "type.googleapis.com/google.crypto.tink.AesCmacKey"))
          .status(),
      IsOk());

  EXPECT_THAT(
      pset.AddPrimitive(
              absl::make_unique<DummyMac>("MAC5"),
              CreateKey(0x01010101, OutputPrefixType::TINK,
                        KeyStatusType::ENABLED, /*type_url=*/
                        "type.googleapis.com/google.crypto.tink.AesCmacKey"))
          .status(),
      IsOk());

  std::vector<MacIdAndTypeUrl> mac_id_and_type;
  for (auto* entry : pset.get_all()) {
    auto mac_or = entry->get_primitive().ComputeMac("");
    ASSERT_THAT(mac_or.status(), IsOk());
    mac_id_and_type.push_back({mac_or.value(), entry->get_identifier(),
                               std::string(entry->get_key_type_url())});
  }

  // In the following id part, the first byte is 1 for Tink.
  std::vector<MacIdAndTypeUrl> expected_result = {
      {/*mac=*/"13:0:DummyMac:MAC1", /*id=*/absl::StrCat("\1\1\1\1\1"),
       /*type_url=*/"type.googleapis.com/google.crypto.tink.HmacKey"},
      {/*mac=*/"13:0:DummyMac:MAC2", /*id=*/absl::StrCat("\1\2\2\2\2"),
       /*type_url=*/"type.googleapis.com/google.crypto.tink.HmacKey"},
      {/*mac=*/"13:0:DummyMac:MAC3", /*id=*/absl::StrCat("\1\2\2\2\2"),
       /*type_url=*/"type.googleapis.com/google.crypto.tink.AesCmacKey"},
      {/*mac=*/"13:0:DummyMac:MAC4", /*id=*/"",
       /*type_url=*/"type.googleapis.com/google.crypto.tink.AesCmacKey"},
      {/*mac=*/"13:0:DummyMac:MAC5", /*id=*/absl::StrCat("\1\1\1\1\1"),
       /*type_url=*/"type.googleapis.com/google.crypto.tink.AesCmacKey"}};

  EXPECT_THAT(mac_id_and_type, UnorderedElementsAreArray(expected_result));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
