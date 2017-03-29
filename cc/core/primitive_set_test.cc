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

#include "cc/primitive_set.h"
#include "cc/crypto_format.h"
#include "cc/mac.h"
#include "cc/util/test_util.h"
#include "google/protobuf/stubs/stringpiece.h"
#include "gtest/gtest.h"
#include "proto/tink.pb.h"

using cloud::crypto::tink::test::DummyMac;
using google::cloud::crypto::tink::Keyset;
using google::cloud::crypto::tink::KeyStatusType;
using google::cloud::crypto::tink::OutputPrefixType;

namespace cloud {
namespace crypto {
namespace tink {
namespace {

class PrimitiveSetTest : public ::testing::Test {
};

TEST_F(PrimitiveSetTest, testBasic) {
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
  Keyset::Key key_1;
  key_1.set_output_prefix_type(OutputPrefixType::TINK);
  key_1.set_key_id(key_id_1);
  key_1.set_status(KeyStatusType::ENABLED);

  uint32_t key_id_2 = 7213743;
  Keyset::Key key_2;
  key_2.set_output_prefix_type(OutputPrefixType::LEGACY);
  key_2.set_key_id(key_id_2);
  key_2.set_status(KeyStatusType::ENABLED);

  uint32_t key_id_3 = key_id_2;    // same id as key_2
  Keyset::Key key_3;
  key_3.set_output_prefix_type(OutputPrefixType::TINK);
  key_3.set_key_id(key_id_3);
  key_3.set_status(KeyStatusType::ENABLED);

  uint32_t key_id_4 = 947327;
  Keyset::Key key_4;
  key_4.set_output_prefix_type(OutputPrefixType::RAW);
  key_4.set_key_id(key_id_4);
  key_4.set_status(KeyStatusType::ENABLED);

  uint32_t key_id_5 = 529472;
  Keyset::Key key_5;
  key_5.set_output_prefix_type(OutputPrefixType::RAW);
  key_5.set_key_id(key_id_5);
  key_5.set_status(KeyStatusType::DISABLED);

  uint32_t key_id_6 = key_id_1;    // same id as key_1
  Keyset::Key key_6;
  key_6.set_output_prefix_type(OutputPrefixType::TINK);
  key_6.set_key_id(key_id_6);
  key_6.set_status(KeyStatusType::DISABLED);

  PrimitiveSet<Mac> primitive_set;
  EXPECT_TRUE(primitive_set.get_primary() == nullptr);
  EXPECT_EQ(util::error::NOT_FOUND,
            primitive_set.get_raw_primitives().status().error_code());
  EXPECT_EQ(util::error::NOT_FOUND,
            primitive_set.get_primitives("prefix").status().error_code());

  // Add all the primitives.
  auto add_primitive_result =
      primitive_set.AddPrimitive(std::move(mac_1), key_1);
  EXPECT_TRUE(add_primitive_result.ok()) << add_primitive_result.status();

  add_primitive_result = primitive_set.AddPrimitive(std::move(mac_2), key_2);
  EXPECT_TRUE(add_primitive_result.ok()) << add_primitive_result.status();

  add_primitive_result = primitive_set.AddPrimitive(std::move(mac_3), key_3);
  EXPECT_TRUE(add_primitive_result.ok()) << add_primitive_result.status();
  primitive_set.set_primary(add_primitive_result.ValueOrDie());

  add_primitive_result = primitive_set.AddPrimitive(std::move(mac_4), key_4);
  EXPECT_TRUE(add_primitive_result.ok()) << add_primitive_result.status();

  add_primitive_result = primitive_set.AddPrimitive(std::move(mac_5), key_5);
  EXPECT_TRUE(add_primitive_result.ok()) << add_primitive_result.status();

  add_primitive_result = primitive_set.AddPrimitive(std::move(mac_6), key_6);
  EXPECT_TRUE(add_primitive_result.ok()) << add_primitive_result.status();

  // Check the primary.
  std::string data = "some data";
  auto primary = primitive_set.get_primary();
  EXPECT_FALSE(primary == nullptr);
  EXPECT_EQ(KeyStatusType::ENABLED, primary->get_status());
  EXPECT_EQ(data + mac_name_3,
            primary->get_primitive().ComputeMac(data).ValueOrDie());

  // Check raw primitives.
  auto primitives = primitive_set.get_raw_primitives().ValueOrDie();
  EXPECT_EQ(2, primitives->size());
  EXPECT_EQ(data + mac_name_4,
            primitives->at(0).get_primitive().ComputeMac(data).ValueOrDie());
  EXPECT_EQ(KeyStatusType::ENABLED, primitives->at(0).get_status());
  EXPECT_EQ(data + mac_name_5,
            primitives->at(1).get_primitive().ComputeMac(data).ValueOrDie());
  EXPECT_EQ(KeyStatusType::DISABLED, primitives->at(1).get_status());

  // Check Tink primitives.
  std::string prefix = CryptoFormat::get_output_prefix(key_1).ValueOrDie();
  primitives = primitive_set.get_primitives(prefix).ValueOrDie();
  EXPECT_EQ(2, primitives->size());
  EXPECT_EQ(data + mac_name_1,
            primitives->at(0).get_primitive().ComputeMac(data).ValueOrDie());
  EXPECT_EQ(KeyStatusType::ENABLED, primitives->at(0).get_status());
  EXPECT_EQ(data + mac_name_6,
            primitives->at(1).get_primitive().ComputeMac(data).ValueOrDie());
  EXPECT_EQ(KeyStatusType::DISABLED, primitives->at(1).get_status());

  prefix = CryptoFormat::get_output_prefix(key_3).ValueOrDie();
  primitives = primitive_set.get_primitives(prefix).ValueOrDie();
  EXPECT_EQ(1, primitives->size());
  EXPECT_EQ(data + mac_name_3,
            primitives->at(0).get_primitive().ComputeMac(data).ValueOrDie());
  EXPECT_EQ(KeyStatusType::ENABLED, primitives->at(0).get_status());

  // Check legacy primitive.
  prefix = CryptoFormat::get_output_prefix(key_2).ValueOrDie();
  primitives = primitive_set.get_primitives(prefix).ValueOrDie();
  EXPECT_EQ(1, primitives->size());
  EXPECT_EQ(data + mac_name_2,
            primitives->at(0).get_primitive().ComputeMac(data).ValueOrDie());
  EXPECT_EQ(KeyStatusType::ENABLED, primitives->at(0).get_status());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
}  // namespace cloud


int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
