// Copyright 2020 Google LLC
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

#include "tink/internal/key_info.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

namespace {

using ::testing::Eq;
using ::google::crypto::tink::Keyset;

TEST(KeyInfoFromKeyTest, Basic) {
  Keyset::Key key;
  key.set_key_id(1234);
  key.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  key.set_status(google::crypto::tink::ENABLED);
  key.mutable_key_data()->set_type_url("MyTypeUrl");

  EXPECT_THAT(KeyInfoFromKey(key).key_id(), Eq(1234));
  EXPECT_THAT(KeyInfoFromKey(key).output_prefix_type(),
              Eq(google::crypto::tink::OutputPrefixType::TINK));
  EXPECT_THAT(KeyInfoFromKey(key).status(), Eq(google::crypto::tink::ENABLED));
  EXPECT_THAT(KeyInfoFromKey(key).type_url(), Eq("MyTypeUrl"));
}

TEST(KeyInfoFromKeyTest, Status) {
  google::crypto::tink::Keyset::Key key;
  key.set_status(google::crypto::tink::ENABLED);
  EXPECT_THAT(KeyInfoFromKey(key).status(), Eq(google::crypto::tink::ENABLED));
  key.set_status(google::crypto::tink::DISABLED);
  EXPECT_THAT(KeyInfoFromKey(key).status(), Eq(google::crypto::tink::DISABLED));
}

TEST(KeyInfoFromKeyTest, OutputPrefixType) {
  google::crypto::tink::Keyset::Key key;
  key.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  EXPECT_THAT(KeyInfoFromKey(key).output_prefix_type(),
              Eq(google::crypto::tink::OutputPrefixType::TINK));
  key.set_output_prefix_type(google::crypto::tink::OutputPrefixType::CRUNCHY);
  EXPECT_THAT(KeyInfoFromKey(key).output_prefix_type(),
              Eq(google::crypto::tink::OutputPrefixType::CRUNCHY));
}

TEST(KeySetInfoForKeySetTest, Basic) {
  Keyset keyset;
  keyset.set_primary_key_id(1234);
  keyset.add_key()->set_key_id(1233);
  keyset.add_key()->set_key_id(1234);
  keyset.add_key()->set_key_id(1235);
  EXPECT_THAT(KeysetInfoFromKeyset(keyset).primary_key_id(), Eq(1234));
  EXPECT_THAT(KeysetInfoFromKeyset(keyset).key_info().size(), Eq(3));
  EXPECT_THAT(KeysetInfoFromKeyset(keyset).key_info(0).key_id(), Eq(1233));
  EXPECT_THAT(KeysetInfoFromKeyset(keyset).key_info(1).key_id(), Eq(1234));
  EXPECT_THAT(KeysetInfoFromKeyset(keyset).key_info(2).key_id(), Eq(1235));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
