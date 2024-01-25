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
////////////////////////////////////////////////////////////////////////////////

#include "tink/keyderivation/keyset_deriver_wrapper.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/keyderivation/keyset_deriver.h"
#include "tink/keyset_handle.h"
#include "tink/primitive_set.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::HasSubstr;

// TODO(b/255828521): Move this to a shared location once KeysetDeriver is in
// the public API.
class DummyDeriver : public KeysetDeriver {
 public:
  explicit DummyDeriver(absl::string_view name) : name_(name) {}
  util::StatusOr<std::unique_ptr<KeysetHandle>> DeriveKeyset(
      absl::string_view salt) const override {
    Keyset::Key key;
    key.mutable_key_data()->set_type_url(
        absl::StrCat(name_.size(), ":", name_, salt));
    key.set_status(KeyStatusType::UNKNOWN_STATUS);
    key.set_key_id(0);
    key.set_output_prefix_type(OutputPrefixType::UNKNOWN_PREFIX);

    Keyset keyset;
    *keyset.add_key() = key;
    keyset.set_primary_key_id(0);
    return CleartextKeysetHandle::GetKeysetHandle(keyset);
  }

 private:
  std::string name_;
};

TEST(KeysetDeriverWrapperTest, WrapNullptr) {
  EXPECT_THAT(KeysetDeriverWrapper().Wrap(nullptr).status(),
              StatusIs(absl::StatusCode::kInternal, HasSubstr("non-NULL")));
}

TEST(KeysetDeriverWrapperTest, WrapEmpty) {
  EXPECT_THAT(
      KeysetDeriverWrapper()
          .Wrap(absl::make_unique<PrimitiveSet<KeysetDeriver>>())
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("no primary")));
}

TEST(KeysetDeriverWrapperTest, WrapNoPrimary) {
  auto deriver_set = absl::make_unique<PrimitiveSet<KeysetDeriver>>();
  KeysetInfo::KeyInfo key_info;
  key_info.set_key_id(1234);
  key_info.set_status(KeyStatusType::ENABLED);
  key_info.set_output_prefix_type(OutputPrefixType::TINK);

  EXPECT_THAT(
      deriver_set->AddPrimitive(absl::make_unique<DummyDeriver>(""), key_info)
          .status(),
      IsOk());

  EXPECT_THAT(
      KeysetDeriverWrapper().Wrap(std::move(deriver_set)).status(),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("no primary")));
}

TEST(KeysetDeriverWrapperTest, WrapSingle) {
  auto deriver_set = absl::make_unique<PrimitiveSet<KeysetDeriver>>();
  KeysetInfo::KeyInfo key_info;
  key_info.set_key_id(1234);
  key_info.set_status(KeyStatusType::ENABLED);
  key_info.set_output_prefix_type(OutputPrefixType::TINK);
  key_info.set_type_url(
      "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey");

  auto entry_or = deriver_set->AddPrimitive(
      absl::make_unique<DummyDeriver>("wrap_single_key"), key_info);
  ASSERT_THAT(entry_or, IsOk());
  EXPECT_THAT(deriver_set->set_primary(entry_or.value()), IsOk());

  auto wrapper_deriver_or = KeysetDeriverWrapper().Wrap(std::move(deriver_set));

  ASSERT_THAT(wrapper_deriver_or, IsOk());

  auto derived_keyset_or =
      wrapper_deriver_or.value()->DeriveKeyset("wrap_single_salt");

  ASSERT_THAT(derived_keyset_or, IsOk());

  Keyset keyset = CleartextKeysetHandle::GetKeyset(*derived_keyset_or.value());

  EXPECT_THAT(keyset.primary_key_id(), Eq(1234));
  ASSERT_THAT(keyset.key_size(), Eq(1));
  EXPECT_THAT(keyset.key(0).key_data().type_url(),
              Eq("15:wrap_single_keywrap_single_salt"));
  EXPECT_THAT(keyset.key(0).status(), Eq(KeyStatusType::ENABLED));
  EXPECT_THAT(keyset.key(0).key_id(), Eq(1234));
  EXPECT_THAT(keyset.key(0).output_prefix_type(), Eq(OutputPrefixType::TINK));
}

TEST(KeysetDeriverWrapperTest, WrapMultiple) {
  auto pset = absl::make_unique<PrimitiveSet<KeysetDeriver>>();
  std::vector<KeysetInfo::KeyInfo> key_infos;

  KeysetInfo::KeyInfo key_info;
  key_info.set_key_id(1010101);
  key_info.set_status(KeyStatusType::ENABLED);
  key_info.set_output_prefix_type(OutputPrefixType::RAW);
  key_info.set_type_url(
      "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey");
  ASSERT_THAT(
      pset->AddPrimitive(absl::make_unique<DummyDeriver>("k1"), key_info)
          .status(),
      IsOk());
  key_infos.push_back(key_info);

  key_info.set_key_id(2020202);
  key_info.set_status(KeyStatusType::ENABLED);
  key_info.set_output_prefix_type(OutputPrefixType::LEGACY);
  key_info.set_type_url(
      "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey");
  util::StatusOr<PrimitiveSet<KeysetDeriver>::Entry<KeysetDeriver>*> entry =
      pset->AddPrimitive(absl::make_unique<DummyDeriver>("k2"), key_info);
  ASSERT_THAT(entry, IsOk());
  ASSERT_THAT(pset->set_primary(*entry), IsOk());
  key_infos.push_back(key_info);

  key_info.set_key_id(3030303);
  key_info.set_status(KeyStatusType::ENABLED);
  key_info.set_output_prefix_type(OutputPrefixType::TINK);
  key_info.set_type_url(
      "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey");
  ASSERT_THAT(
      pset->AddPrimitive(absl::make_unique<DummyDeriver>("k3"), key_info),
      IsOk());
  key_infos.push_back(key_info);

  util::StatusOr<std::unique_ptr<KeysetDeriver>> wrapper_deriver =
      KeysetDeriverWrapper().Wrap(std::move(pset));
  ASSERT_THAT(wrapper_deriver, IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> derived_keyset =
      (*wrapper_deriver)->DeriveKeyset("salt");
  ASSERT_THAT(derived_keyset, IsOk());
  Keyset keyset = CleartextKeysetHandle::GetKeyset(**derived_keyset);

  EXPECT_THAT(keyset.primary_key_id(), Eq(2020202));
  ASSERT_THAT(keyset.key_size(), Eq(3));

  for (int i = 0; i < keyset.key().size(); i++) {
    std::string type_url = absl::StrCat("2:k", i + 1, "salt");
    EXPECT_THAT(keyset.key(i).key_data().type_url(), Eq(type_url));

    Keyset::Key key = keyset.key(i);
    key_info = key_infos[i];
    EXPECT_THAT(key.status(), Eq(key_info.status()));
    EXPECT_THAT(key.key_id(), Eq(key_info.key_id()));
    EXPECT_THAT(key.output_prefix_type(), Eq(key_info.output_prefix_type()));
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
