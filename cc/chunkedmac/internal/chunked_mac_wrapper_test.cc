// Copyright 2022 Google LLC
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

#include "tink/chunkedmac/internal/chunked_mac_wrapper.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "tink/chunked_mac.h"
#include "tink/chunkedmac/internal/chunked_mac_impl.h"
#include "tink/subtle/mac/stateful_mac.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeysetInfo;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Values;

class FakeStatefulMac : public subtle::StatefulMac {
 public:
  explicit FakeStatefulMac(absl::string_view name) : name_(name) {}

  util::Status Update(absl::string_view data) override {
    absl::StrAppend(&buffer_, data);
    return util::OkStatus();
  }

  util::StatusOr<std::string> Finalize() override {
    return absl::StrCat(name_, buffer_);
  }

 private:
  const std::string name_;
  std::string buffer_ = "";
};

class FakeStatefulMacFactory : public subtle::StatefulMacFactory {
 public:
  explicit FakeStatefulMacFactory(absl::string_view name) : name_(name) {}

  util::StatusOr<std::unique_ptr<subtle::StatefulMac>> Create() const override {
    return std::unique_ptr<subtle::StatefulMac>(
        absl::make_unique<FakeStatefulMac>(name_));
  }

 private:
  std::string name_;
};

TEST(ChunkedMacWrapperTest, WrapNullptr) {
  EXPECT_THAT(ChunkedMacWrapper().Wrap(nullptr).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(ChunkedMacWrapperTest, WrapEmpty) {
  std::unique_ptr<PrimitiveSet<ChunkedMac>> mac_set(
      new PrimitiveSet<ChunkedMac>());
  EXPECT_THAT(ChunkedMacWrapper().Wrap(std::move(mac_set)).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

std::unique_ptr<ChunkedMac> CreateFakeChunkedMac(absl::string_view name) {
  return absl::make_unique<ChunkedMacImpl>(
      absl::make_unique<FakeStatefulMacFactory>(name));
}

util::Status AddPrimitiveToSet(uint32_t key_id, bool set_primary,
                               OutputPrefixType output_prefix_type,
                               std::unique_ptr<ChunkedMac> mac,
                               KeysetInfo& keyset_info,
                               PrimitiveSet<ChunkedMac>& mac_set) {
  int index = keyset_info.key_info_size();
  KeysetInfo::KeyInfo* key_info = keyset_info.add_key_info();
  key_info->set_output_prefix_type(output_prefix_type);
  key_info->set_key_id(key_id);
  key_info->set_status(KeyStatusType::ENABLED);

  auto entry =
      mac_set.AddPrimitive(std::move(mac), keyset_info.key_info(index));
  if (!entry.ok()) {
    return entry.status();
  }
  if (set_primary) {
    util::Status set_primary_status = mac_set.set_primary(*entry);
    if (!set_primary_status.ok()) {
      return set_primary_status;
    }
  }
  return util::OkStatus();
}

TEST(ChunkedMacWrapperTest, ComputeMac) {
  KeysetInfo keyset_info;
  auto mac_set = absl::make_unique<PrimitiveSet<ChunkedMac>>();

  // Add primitives to the primitive set.
  ASSERT_THAT(
      AddPrimitiveToSet(
          /*key_id=*/0x12d66f, /*set_primary=*/false, OutputPrefixType::TINK,
          CreateFakeChunkedMac("chunkedmac0:"), keyset_info, *mac_set),
      IsOk());
  ASSERT_THAT(
      AddPrimitiveToSet(
          /*key_id=*/0xb1539, /*set_primary=*/false, OutputPrefixType::LEGACY,
          CreateFakeChunkedMac("chunkedmac1:"), keyset_info, *mac_set),
      IsOk());
  ASSERT_THAT(
      AddPrimitiveToSet(
          /*key_id=*/0x6e12af, /*set_primary=*/true, OutputPrefixType::TINK,
          CreateFakeChunkedMac("chunkedmac2:"), keyset_info, *mac_set),
      IsOk());

  // Wrap primitive set into a ChunkedMac.
  util::StatusOr<std::unique_ptr<crypto::tink::ChunkedMac>> chunked_mac =
      ChunkedMacWrapper().Wrap(std::move(mac_set));
  ASSERT_THAT(chunked_mac.status(), IsOk());

  util::StatusOr<std::unique_ptr<ChunkedMacComputation>> computation =
      (*chunked_mac)->CreateComputation();
  EXPECT_THAT(computation.status(), IsOk());
  EXPECT_THAT((*computation)->Update("inputdata"), IsOk());
  util::StatusOr<std::string> tag = (*computation)->ComputeMac();
  const std::string output_prefix = std::string("\x01\x00\x6e\x12\xaf", 5);
  const std::string raw_tag = "chunkedmac2:inputdata";
  EXPECT_THAT(tag, IsOkAndHolds(absl::StrCat(output_prefix, raw_tag)));
}

TEST(ChunkedMacWrapperTest, VerifyMacWithUniquePrefix) {
  KeysetInfo keyset_info;
  auto mac_set = absl::make_unique<PrimitiveSet<ChunkedMac>>();

  // Add primitives to primitive set.
  ASSERT_THAT(
      AddPrimitiveToSet(
          /*key_id=*/0x12d66f, /*set_primary=*/false, OutputPrefixType::TINK,
          CreateFakeChunkedMac("chunkedmac0:"), keyset_info, *mac_set),
      IsOk());
  ASSERT_THAT(
      AddPrimitiveToSet(
          /*key_id=*/0xb1539, /*set_primary=*/false, OutputPrefixType::LEGACY,
          CreateFakeChunkedMac("chunkedmac1:"), keyset_info, *mac_set),
      IsOk());
  ASSERT_THAT(
      AddPrimitiveToSet(
          /*key_id=*/0x6e12af, /*set_primary=*/true, OutputPrefixType::TINK,
          CreateFakeChunkedMac("chunkedmac2:"), keyset_info, *mac_set),
      IsOk());

  // Wrap primitive set into a ChunkedMac.
  util::StatusOr<std::unique_ptr<crypto::tink::ChunkedMac>>
      chunked_mac = ChunkedMacWrapper().Wrap(std::move(mac_set));
  ASSERT_THAT(chunked_mac.status(), IsOk());

  const std::string output_prefix = std::string("\x01\x00\x6e\x12\xaf", 5);
  const std::string raw_tag = "chunkedmac2:inputdata";
  util::StatusOr<std::unique_ptr<ChunkedMacVerification>> verification =
      (*chunked_mac)
          ->CreateVerification(absl::StrCat(output_prefix, raw_tag));
  EXPECT_THAT(verification.status(), IsOk());
  EXPECT_THAT((*verification)->Update("inputdata"), IsOk());
  EXPECT_THAT((*verification)->VerifyMac(), IsOk());
}

TEST(ChunkedMacWrapperTest, VerifyMacWithDuplicatePrefix) {
  KeysetInfo keyset_info;
  auto mac_set = absl::make_unique<PrimitiveSet<ChunkedMac>>();

  // Add primitives to primitive set.
  ASSERT_THAT(
      AddPrimitiveToSet(
          /*key_id=*/0x12d66f, /*set_primary=*/false, OutputPrefixType::LEGACY,
          CreateFakeChunkedMac("chunkedmac0:"), keyset_info, *mac_set),
      IsOk());
  ASSERT_THAT(
      AddPrimitiveToSet(
          /*key_id=*/0x6e12af, /*set_primary=*/false, OutputPrefixType::TINK,
          CreateFakeChunkedMac("chunkedmac1:"), keyset_info, *mac_set),
      IsOk());
  ASSERT_THAT(
      AddPrimitiveToSet(
          /*key_id=*/0x6e12af, /*set_primary=*/true, OutputPrefixType::TINK,
          CreateFakeChunkedMac("chunkedmac2:"), keyset_info, *mac_set),
      IsOk());

  // Wrap primitive set into a ChunkedMac.
  util::StatusOr<std::unique_ptr<crypto::tink::ChunkedMac>>
      chunked_mac = ChunkedMacWrapper().Wrap(std::move(mac_set));
  ASSERT_THAT(chunked_mac.status(), IsOk());

  const std::string output_prefix = std::string("\x01\x00\x6e\x12\xaf", 5);
  const std::string raw_tag = "chunkedmac1:inputdata";
  util::StatusOr<std::unique_ptr<ChunkedMacVerification>> verification =
      (*chunked_mac)
          ->CreateVerification(absl::StrCat(output_prefix, raw_tag));
  EXPECT_THAT(verification.status(), IsOk());
  EXPECT_THAT((*verification)->Update("inputdata"), IsOk());
  EXPECT_THAT((*verification)->VerifyMac(), IsOk());
}

TEST(ChunkedMacWrapperTest, VerifyMacWithRawTagStartingWithKeyId) {
  KeysetInfo keyset_info;
  auto mac_set = absl::make_unique<PrimitiveSet<ChunkedMac>>();

  const std::string key_id0 = std::string("\x01\x00\x12\xd6\x6f", 5);

  // Add primitives to primitive set.
  ASSERT_THAT(
      AddPrimitiveToSet(
          /*key_id=*/0x12d66f, /*set_primary=*/false, OutputPrefixType::TINK,
          CreateFakeChunkedMac("chunkedmac0:"), keyset_info, *mac_set),
      IsOk());
  ASSERT_THAT(
      AddPrimitiveToSet(
          /*key_id=*/0x6e12af, /*set_primary=*/true, OutputPrefixType::RAW,
          CreateFakeChunkedMac(/*name=*/absl::StrCat(key_id0, ":chunkedmac1:")),
          keyset_info, *mac_set),
      IsOk());

  // Wrap primitive set into a ChunkedMac.
  util::StatusOr<std::unique_ptr<crypto::tink::ChunkedMac>>
      chunked_mac = ChunkedMacWrapper().Wrap(std::move(mac_set));
  ASSERT_THAT(chunked_mac.status(), IsOk());

  const std::string raw_tag = absl::StrCat(key_id0, ":chunkedmac1:inputdata");
  util::StatusOr<std::unique_ptr<ChunkedMacVerification>> verification =
      (*chunked_mac)->CreateVerification(raw_tag);
  EXPECT_THAT(verification.status(), IsOk());
  EXPECT_THAT((*verification)->Update("inputdata"), IsOk());
  EXPECT_THAT((*verification)->VerifyMac(), IsOk());
}

class ChunkedMacWrapperOutputPrefixTest
    : public testing::TestWithParam<OutputPrefixType> {};

INSTANTIATE_TEST_SUITE_P(
    ChunkedMacWrapperOutputPrefixTestSuite, ChunkedMacWrapperOutputPrefixTest,
    Values(OutputPrefixType::LEGACY, OutputPrefixType::RAW,
           OutputPrefixType::CRUNCHY, OutputPrefixType::TINK));

TEST_P(ChunkedMacWrapperOutputPrefixTest, ComputeVerifyMac) {
  OutputPrefixType output_prefix_type = GetParam();

  KeysetInfo keyset_info;
  auto mac_set = absl::make_unique<PrimitiveSet<ChunkedMac>>();

  // Add primitives to primitive set.
  ASSERT_THAT(
      AddPrimitiveToSet(
          /*key_id=*/0x12d66f, /*set_primary=*/true, output_prefix_type,
          CreateFakeChunkedMac("chunkedmac:"), keyset_info, *mac_set),
      IsOk());

  // Wrap primitive set into a ChunkedMac.
  util::StatusOr<std::unique_ptr<crypto::tink::ChunkedMac>> chunked_mac =
      ChunkedMacWrapper().Wrap(std::move(mac_set));
  ASSERT_THAT(chunked_mac.status(), IsOk());

  // Compute MAC via wrapper.
  util::StatusOr<std::unique_ptr<ChunkedMacComputation>> mac_computation =
      (*chunked_mac)->CreateComputation();
  ASSERT_THAT(mac_computation.status(), IsOk());
  ASSERT_THAT((*mac_computation)->Update("inputdata"), IsOk());
  util::StatusOr<std::string> tag = (*mac_computation)->ComputeMac();
  ASSERT_THAT(tag.status(), IsOk());

  // Verify MAC via wrapper.
  util::StatusOr<std::unique_ptr<ChunkedMacVerification>> mac_verification =
      (*chunked_mac)->CreateVerification(*tag);
  ASSERT_THAT(mac_verification.status(), IsOk());
  ASSERT_THAT((*mac_verification)->Update("inputdata"), IsOk());
  ASSERT_THAT((*mac_verification)->VerifyMac(), IsOk());
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
