// Copyright 2019 Google LLC
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

#include "tink/util/validation.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {

namespace {

using crypto::tink::test::IsOk;
using crypto::tink::test::StatusIs;
using google::crypto::tink::KeyData;
using testing::Not;

TEST(ValidateKey, ValidKey) {
  google::crypto::tink::Keyset::Key key;
  key.set_key_id(100);
  key.mutable_key_data()->set_value("some value");
  key.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  key.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  EXPECT_THAT(crypto::tink::ValidateKey(key), IsOk());
}

TEST(ValidateKey, MissingOutputPrefixType) {
  google::crypto::tink::Keyset::Key key;
  key.set_key_id(100);
  key.mutable_key_data()->set_value("some value");
  key.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  EXPECT_THAT(crypto::tink::ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(ValidateKey, MissingKeyData) {
  google::crypto::tink::Keyset::Key key;
  key.set_key_id(100);
  key.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  key.set_status(google::crypto::tink::KeyStatusType::ENABLED);
  EXPECT_THAT(crypto::tink::ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(ValidateKey, MissingStatus) {
  google::crypto::tink::Keyset::Key key;
  key.set_key_id(100);
  key.mutable_key_data()->set_value("some value");
  key.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  EXPECT_THAT(crypto::tink::ValidateKey(key),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(ValidateKeyset, Valid) {
  google::crypto::tink::Keyset keyset;
  google::crypto::tink::Keyset::Key* key = keyset.add_key();
  key->set_key_id(100);
  key->mutable_key_data()->set_value("some value");
  key->set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  key->set_status(google::crypto::tink::KeyStatusType::ENABLED);
  keyset.set_primary_key_id(100);
  EXPECT_THAT(crypto::tink::ValidateKeyset(keyset), IsOk());
}

TEST(ValidateKeyset, ValidMultipleKeys) {
  google::crypto::tink::Keyset keyset;
  google::crypto::tink::Keyset::Key* key = keyset.add_key();
  key->set_key_id(32);
  key->mutable_key_data()->set_value("some value");
  key->set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  key->set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key = keyset.add_key();
  key->set_key_id(100);
  key->mutable_key_data()->set_value("some other value");
  key->set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  key->set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key = keyset.add_key();
  key->set_key_id(18);
  key->mutable_key_data()->set_value("some third value");
  key->set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  key->set_status(google::crypto::tink::KeyStatusType::ENABLED);
  keyset.set_primary_key_id(100);
  EXPECT_THAT(crypto::tink::ValidateKeyset(keyset), IsOk());
}

// Tests that a keyset with duplicate primary id is rejected
TEST(ValidateKeyset, DuplicatePrimaryId) {
  google::crypto::tink::Keyset keyset;
  google::crypto::tink::Keyset::Key* key = keyset.add_key();
  key->set_key_id(100);
  key->mutable_key_data()->set_value("some value");
  key->set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  key->set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key = keyset.add_key();
  key->set_key_id(100);
  key->mutable_key_data()->set_value("some other value");
  key->set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  key->set_status(google::crypto::tink::KeyStatusType::ENABLED);
  keyset.set_primary_key_id(100);
  EXPECT_THAT(crypto::tink::ValidateKeyset(keyset), Not(IsOk()));
}

// Tests that a keyset with public keys only doesn't need a primary id
TEST(ValidateKeyset, OnlyPublicKeys) {
  google::crypto::tink::Keyset keyset;
  google::crypto::tink::Keyset::Key* key = keyset.add_key();
  key->set_key_id(32);
  key->mutable_key_data()->set_value("some value");
  key->mutable_key_data()->set_key_material_type(KeyData::ASYMMETRIC_PUBLIC);
  key->set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  key->set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key = keyset.add_key();
  key->set_key_id(100);
  key->mutable_key_data()->set_value("some other value");
  key->mutable_key_data()->set_key_material_type(KeyData::ASYMMETRIC_PUBLIC);
  key->set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  key->set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key = keyset.add_key();
  key->set_key_id(18);
  key->mutable_key_data()->set_value("some third value");
  key->mutable_key_data()->set_key_material_type(KeyData::ASYMMETRIC_PUBLIC);
  key->set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  key->set_status(google::crypto::tink::KeyStatusType::ENABLED);
  EXPECT_THAT(crypto::tink::ValidateKeyset(keyset), IsOk());
}

TEST(ValidateKeyset, PrimaryIdNonExistent) {
  google::crypto::tink::Keyset keyset;
  google::crypto::tink::Keyset::Key* key = keyset.add_key();
  key->set_key_id(100);
  key->mutable_key_data()->set_value("some value");
  key->set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  key->set_status(google::crypto::tink::KeyStatusType::ENABLED);
  keyset.set_primary_key_id(99);
  EXPECT_THAT(crypto::tink::ValidateKeyset(keyset),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(ValidateKeyset, ValidHighId) {
  google::crypto::tink::Keyset keyset;
  google::crypto::tink::Keyset::Key* key = keyset.add_key();
  key->set_key_id(std::numeric_limits<uint32_t>::max());
  key->mutable_key_data()->set_value("some value");
  key->set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  key->set_status(google::crypto::tink::KeyStatusType::ENABLED);
  keyset.set_primary_key_id(std::numeric_limits<uint32_t>::max());
  EXPECT_THAT(crypto::tink::ValidateKeyset(keyset), IsOk());
}

}  // namespace

}  // namespace tink
}  // namespace crypto
