// Copyright 2023 Google Inc.
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

#include "tink/keyderivation/internal/keyset_deriver_set_wrapper_impl.h"

#include <memory>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/crypto_format.h"
#include "tink/keyderivation/keyset_deriver.h"
#include "tink/primitive_set.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::SizeIs;

// TODO(b/255828521): Move this to a shared location once KeysetDeriver is in
// the public API.
class DummyDeriver : public KeysetDeriver {
 public:
  explicit DummyDeriver() = default;
  crypto::tink::util::StatusOr<std::unique_ptr<KeysetHandle>> DeriveKeyset(
      absl::string_view salt) const override {
    Keyset keyset;
    return CleartextKeysetHandle::GetKeysetHandle(keyset);
  }
};

TEST(KeysetDeriverSetWrapperImpl, GetAllInKeysetOrder) {
  auto pset = absl::make_unique<PrimitiveSet<KeysetDeriver>>();
  std::vector<KeysetInfo::KeyInfo> key_infos;

  KeysetInfo::KeyInfo key_info;
  key_info.set_key_id(1010101);
  key_info.set_status(KeyStatusType::ENABLED);
  key_info.set_output_prefix_type(OutputPrefixType::RAW);
  key_info.set_type_url(
      "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey");
  ASSERT_THAT(pset->AddPrimitive(absl::make_unique<DummyDeriver>(), key_info),
              IsOk());
  key_infos.push_back(key_info);

  key_info.set_key_id(2020202);
  key_info.set_status(KeyStatusType::ENABLED);
  key_info.set_output_prefix_type(OutputPrefixType::LEGACY);
  key_info.set_type_url(
      "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey");
  ASSERT_THAT(pset->AddPrimitive(absl::make_unique<DummyDeriver>(), key_info),
              IsOk());
  key_infos.push_back(key_info);

  key_info.set_key_id(3030303);
  key_info.set_status(KeyStatusType::ENABLED);
  key_info.set_output_prefix_type(OutputPrefixType::TINK);
  key_info.set_type_url(
      "type.googleapis.com/google.crypto.tink.PrfBasedDeriverKey");
  ASSERT_THAT(pset->AddPrimitive(absl::make_unique<DummyDeriver>(), key_info),
              IsOk());
  key_infos.push_back(key_info);

  // Should not be returned by get_all_in_keyset_order() because the type URL is
  // not PrfBasedDeriverKey.
  key_info.set_key_id(4040404);
  key_info.set_status(KeyStatusType::ENABLED);
  key_info.set_output_prefix_type(OutputPrefixType::TINK);
  key_info.set_type_url("type.googleapis.com/google.crypto.tink.AesGcmKey");
  ASSERT_THAT(pset->AddPrimitive(absl::make_unique<DummyDeriver>(), key_info),
              IsOk());

  std::vector<PrimitiveSet<KeysetDeriver>::Entry<KeysetDeriver>*> entries =
      KeysetDeriverSetWrapperImpl::get_all_in_keyset_order(*pset);
  EXPECT_THAT(entries, SizeIs(key_infos.size()));

  for (int i = 0; i < entries.size(); i++) {
    EXPECT_THAT(entries[i]->get_identifier(),
                Eq(*CryptoFormat::GetOutputPrefix(key_infos[i])));
    EXPECT_THAT(entries[i]->get_status(), Eq(KeyStatusType::ENABLED));
    EXPECT_THAT(entries[i]->get_key_id(), Eq(key_infos[i].key_id()));
    EXPECT_THAT(entries[i]->get_output_prefix_type(),
                Eq(key_infos[i].output_prefix_type()));
    EXPECT_THAT(entries[i]->get_key_type_url(), Eq(key_infos[i].type_url()));
  }
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
