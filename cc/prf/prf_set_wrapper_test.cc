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
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;
using ::testing::Key;
using ::testing::NiceMock;
using ::testing::Not;
using ::testing::Return;
using ::testing::ReturnRef;
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

class FakePrfSet : public PrfSet {
 public:
  FakePrfSet(uint32_t primary_id, const std::map<uint32_t, Prf*>& prfs)
      : primary_id_(primary_id), prfs_(prfs) {}
  uint32_t GetPrimaryId() const override { return primary_id_; }
  const std::map<uint32_t, Prf*>& GetPrfs() const override { return prfs_; }

 private:
  uint32_t primary_id_;
  std::map<uint32_t, Prf*> prfs_;
};

class PrfSetWrapperTest : public ::testing::Test {
 protected:
  void SetUp() override {
    prf_set_primitive_set_ = absl::make_unique<PrimitiveSet<PrfSet>>();
  }
  void AddPrf(uint32_t id, const std::string& output) {
    auto prf = absl::make_unique<FakePrf>(output);
    prf_map_.insert({id, prf.get()});
    prfs_.push_back(std::move(prf));
  }
  PrimitiveSet<PrfSet>::Entry<PrfSet>* AddPrfSet(uint32_t primary_id,
                                                 Keyset::Key key) {
    auto prf = absl::make_unique<FakePrfSet>(primary_id, prf_map_);
    prf_map_.clear();
    auto entry_or = prf_set_primitive_set_->AddPrimitive(std::move(prf), key);
    EXPECT_THAT(entry_or.status(), IsOk());
    return entry_or.ValueOrDie();
  }

  Keyset::Key MakeKey(uint32_t id) {
    Keyset::Key key;
    key.set_output_prefix_type(google::crypto::tink::OutputPrefixType::RAW);
    key.set_key_id(id);
    key.set_status(KeyStatusType::ENABLED);
    return key;
  }

  PrimitiveSet<PrfSet>* prf_set_primitive_set() {
    return prf_set_primitive_set_.get();
  }
  std::unique_ptr<PrimitiveSet<PrfSet>> ReleasePrimitiveSet() {
    return std::unique_ptr<PrimitiveSet<PrfSet>>(
        prf_set_primitive_set_.release());
  }

 private:
  std::map<uint32_t, Prf*> prf_map_;
  std::vector<std::unique_ptr<Prf>> prfs_;
  std::unique_ptr<PrimitiveSet<PrfSet>> prf_set_primitive_set_;
};

TEST_F(PrfSetWrapperTest, NullPrfSet) {
  PrfSetWrapper wrapper;
  EXPECT_THAT(wrapper.Wrap(nullptr).status(), Not(IsOk()));
}

TEST_F(PrfSetWrapperTest, EmptyPrfSet) {
  PrfSetWrapper wrapper;
  EXPECT_THAT(wrapper.Wrap(absl::make_unique<PrimitiveSet<PrfSet>>()).status(),
              Not(IsOk()));
}

TEST_F(PrfSetWrapperTest, NonRawKeyType) {
  Keyset::Key key = MakeKey(1);
  key.set_output_prefix_type(google::crypto::tink::OutputPrefixType::TINK);
  AddPrf(1, "output");
  ASSERT_THAT(prf_set_primitive_set()->set_primary(AddPrfSet(1, key)), IsOk());
  PrfSetWrapper wrapper;
  EXPECT_THAT(wrapper.Wrap(ReleasePrimitiveSet()).status(), Not(IsOk()));
}

TEST_F(PrfSetWrapperTest, TooManyPrfs) {
  AddPrf(1, "output");
  AddPrf(2, "output");
  ASSERT_THAT(prf_set_primitive_set()->set_primary(AddPrfSet(1, MakeKey(1))),
              IsOk());
  PrfSetWrapper wrapper;
  EXPECT_THAT(wrapper.Wrap(ReleasePrimitiveSet()).status(), Not(IsOk()));
}

TEST_F(PrfSetWrapperTest, TooFewPrfs) {
  Keyset::Key key = MakeKey(1);
  ASSERT_THAT(prf_set_primitive_set()->set_primary(AddPrfSet(1, MakeKey(1))),
              IsOk());
  PrfSetWrapper wrapper;
  EXPECT_THAT(wrapper.Wrap(ReleasePrimitiveSet()).status(), Not(IsOk()));
}

TEST_F(PrfSetWrapperTest, WrapOkay) {
  AddPrf(1, "output");
  ASSERT_THAT(prf_set_primitive_set()->set_primary(AddPrfSet(1, MakeKey(1))),
              IsOk());
  PrfSetWrapper wrapper;
  auto wrapped = wrapper.Wrap(ReleasePrimitiveSet());
  ASSERT_THAT(wrapped.status(), IsOk());
  EXPECT_THAT(wrapped.ValueOrDie()->ComputePrimary("input", 6),
              IsOkAndHolds(StrEq("output")));
}

TEST_F(PrfSetWrapperTest, WrapTwo) {
  std::string primary_output("output");
  AddPrf(1, primary_output);
  ASSERT_THAT(prf_set_primitive_set()->set_primary(AddPrfSet(1, MakeKey(1))),
              IsOk());
  std::string secondary_output("different");
  AddPrf(1, secondary_output);
  AddPrfSet(1, MakeKey(2));
  PrfSetWrapper wrapper;
  auto wrapped_or = wrapper.Wrap(ReleasePrimitiveSet());
  ASSERT_THAT(wrapped_or.status(), IsOk());
  auto wrapped = std::move(wrapped_or.ValueOrDie());
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
