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
#include "tink/prf/prf_set_wrapper.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "tink/prf/prf_set.h"
#include "tink/primitive_set.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::testing::Key;
using ::testing::Not;
using ::testing::StrEq;
using ::testing::UnorderedElementsAre;

class FakePrf : public Prf {
 public:
  explicit FakePrf(const std::string& output) : output_(output) {}
  util::StatusOr<std::string> Compute(absl::string_view input,
                                      size_t output_length) const override {
    return output_;
  }

 private:
  std::string output_;
};

class PrfSetWrapperTest : public ::testing::Test {
 protected:
  void SetUp() override { prf_set_ = absl::make_unique<PrimitiveSet<Prf>>(); }

  util::StatusOr<PrimitiveSet<Prf>::Entry<Prf>*> AddPrf(
      const std::string& output, const KeysetInfo::KeyInfo& key_info) {
    auto prf = absl::make_unique<FakePrf>(output);
    return prf_set_->AddPrimitive(std::move(prf), key_info);
  }

  KeysetInfo::KeyInfo MakeKey(uint32_t id) {
    KeysetInfo::KeyInfo key;
    key.set_output_prefix_type(google::crypto::tink::OutputPrefixType::RAW);
    key.set_key_id(id);
    key.set_status(KeyStatusType::ENABLED);
    return key;
  }

  std::unique_ptr<PrimitiveSet<Prf>>& PrfSet() { return prf_set_; }

 private:
  std::unique_ptr<PrimitiveSet<Prf>> prf_set_;
};

TEST_F(PrfSetWrapperTest, NullPrfSet) {
  PrfSetWrapper wrapper;
  EXPECT_THAT(wrapper.Wrap(nullptr).status(), Not(IsOk()));
}

TEST_F(PrfSetWrapperTest, EmptyPrfSet) {
  PrfSetWrapper wrapper;
  EXPECT_THAT(wrapper.Wrap(absl::make_unique<PrimitiveSet<Prf>>()).status(),
              Not(IsOk()));
}

TEST_F(PrfSetWrapperTest, NonRawKeyType) {
  KeysetInfo::KeyInfo key_info = MakeKey(1);
  key_info.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  auto entry = AddPrf("output", key_info);
  ASSERT_THAT(entry.status(), IsOk());
  ASSERT_THAT(PrfSet()->set_primary(entry.value()), IsOk());
  PrfSetWrapper wrapper;
  EXPECT_THAT(wrapper.Wrap(std::move(PrfSet())).status(), Not(IsOk()));
}

TEST_F(PrfSetWrapperTest, WrapOkay) {
  auto entry = AddPrf("output", MakeKey(1));
  ASSERT_THAT(entry.status(), IsOk());
  ASSERT_THAT(PrfSet()->set_primary(entry.value()), IsOk());
  PrfSetWrapper wrapper;
  auto wrapped = wrapper.Wrap(std::move(PrfSet()));
  ASSERT_THAT(wrapped.status(), IsOk());
  EXPECT_THAT(wrapped.value()->ComputePrimary("input", 6),
              IsOkAndHolds(StrEq("output")));
}

TEST_F(PrfSetWrapperTest, WrapTwo) {
  std::string primary_output("output");
  auto entry = AddPrf(primary_output, MakeKey(1));
  ASSERT_THAT(entry.status(), IsOk());
  ASSERT_THAT(PrfSet()->set_primary(entry.value()), IsOk());

  ASSERT_THAT(AddPrf(primary_output, MakeKey(1)).status(), IsOk());
  std::string secondary_output("different");
  ASSERT_THAT(AddPrf(secondary_output, MakeKey(2)).status(), IsOk());
  PrfSetWrapper wrapper;
  auto wrapped_or = wrapper.Wrap(std::move(PrfSet()));
  ASSERT_THAT(wrapped_or.status(), IsOk());
  auto wrapped = std::move(wrapped_or.value());
  EXPECT_THAT(wrapped->ComputePrimary("input", 6),
              IsOkAndHolds(StrEq("output")));
  const auto& prf_map = wrapped->GetPrfs();
  ASSERT_THAT(prf_map, UnorderedElementsAre(Key(1), Key(2)));
  EXPECT_THAT(prf_map.find(1)->second->Compute("input", 6),
              IsOkAndHolds(StrEq("output")));
  EXPECT_THAT(prf_map.find(2)->second->Compute("input", 6),
              IsOkAndHolds(StrEq("different")));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
