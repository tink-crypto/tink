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

#include <memory>
#include <string>
#include <tuple>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/chunked_mac.h"
#include "tink/keyset_handle.h"
#include "tink/mac.h"
#include "tink/mac/mac_config.h"
#include "tink/mac/mac_key_templates.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::MacKeyTemplates;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::Combine;
using ::testing::Values;

class ChunkedMacCompatibilityTest
    : public testing::TestWithParam<std::tuple<KeyTemplate, OutputPrefixType>> {
};

INSTANTIATE_TEST_SUITE_P(
    ChunkedMacCompatibilityTestSuite, ChunkedMacCompatibilityTest,
    Combine(Values(MacKeyTemplates::AesCmac(), MacKeyTemplates::HmacSha256()),
            Values(OutputPrefixType::LEGACY, OutputPrefixType::RAW,
                   OutputPrefixType::CRUNCHY, OutputPrefixType::TINK)));

TEST_P(ChunkedMacCompatibilityTest, ComputeAndVerify) {
  KeyTemplate key_template;
  OutputPrefixType output_prefix_type;
  std::tie(key_template, output_prefix_type) = GetParam();
  key_template.set_output_prefix_type(output_prefix_type);

  ASSERT_THAT(MacConfig::Register(), IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> key =
      KeysetHandle::GenerateNew(key_template);
  ASSERT_THAT(key, IsOk());

  util::StatusOr<std::unique_ptr<Mac>> mac = (*key)->GetPrimitive<Mac>();
  ASSERT_THAT(mac, IsOk());

  util::StatusOr<std::unique_ptr<ChunkedMac>> chunked_mac =
      (*key)->GetPrimitive<ChunkedMac>();
  ASSERT_THAT(chunked_mac, IsOk());

  // Compute tag with chunked MAC.
  util::StatusOr<std::unique_ptr<ChunkedMacComputation>> computation =
      (*chunked_mac)->CreateComputation();
  ASSERT_THAT(computation, IsOk());
  ASSERT_THAT((*computation)->Update("abc"), IsOk());
  ASSERT_THAT((*computation)->Update("xyz"), IsOk());
  util::StatusOr<std::string> chunked_tag = (*computation)->ComputeMac();
  ASSERT_THAT(chunked_tag, IsOk());

  // Verify tag with regular MAC.
  ASSERT_THAT((*mac)->VerifyMac(*chunked_tag, "abcxyz"), IsOk());

  // Compute tag with regular MAC.
  util::StatusOr<std::string> tag = (*mac)->ComputeMac("abcxyz");
  ASSERT_THAT(tag, IsOk());
  ASSERT_THAT(*tag, Eq(*chunked_tag));

  // Verify tag with chunked MAC.
  util::StatusOr<std::unique_ptr<ChunkedMacVerification>> verification =
      (*chunked_mac)->CreateVerification(*tag);
  ASSERT_THAT(verification, IsOk());
  ASSERT_THAT((*verification)->Update("abc"), IsOk());
  ASSERT_THAT((*verification)->Update("xyz"), IsOk());
  EXPECT_THAT((*verification)->VerifyMac(), IsOk());
}

TEST(ChunkedMacSlicingTest, DifferentChunkSizes) {
  ASSERT_THAT(MacConfig::Register(), IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> key =
      KeysetHandle::GenerateNew(MacKeyTemplates::HmacSha256());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<std::unique_ptr<ChunkedMac>> chunked_mac =
      (*key)->GetPrimitive<ChunkedMac>();
  ASSERT_THAT(chunked_mac, IsOk());

  // Update three input chunks.
  util::StatusOr<std::unique_ptr<ChunkedMacComputation>> computation =
      (*chunked_mac)->CreateComputation();
  ASSERT_THAT(computation, IsOk());
  ASSERT_THAT((*computation)->Update("ab"), IsOk());
  ASSERT_THAT((*computation)->Update("cx"), IsOk());
  ASSERT_THAT((*computation)->Update("yz"), IsOk());
  util::StatusOr<std::string> tag = (*computation)->ComputeMac();
  ASSERT_THAT(tag, IsOk());

  // Update two input chunks.
  util::StatusOr<std::unique_ptr<ChunkedMacVerification>> verification =
      (*chunked_mac)->CreateVerification(*tag);
  ASSERT_THAT(verification, IsOk());
  ASSERT_THAT((*verification)->Update("abc"), IsOk());
  ASSERT_THAT((*verification)->Update("xyz"), IsOk());
  EXPECT_THAT((*verification)->VerifyMac(), IsOk());
}

TEST(ChunkedMacTest, VerifyPrefixFails) {
  ASSERT_THAT(MacConfig::Register(), IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> key =
      KeysetHandle::GenerateNew(MacKeyTemplates::HmacSha256());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<std::unique_ptr<ChunkedMac>> chunked_mac =
      (*key)->GetPrimitive<ChunkedMac>();
  ASSERT_THAT(chunked_mac, IsOk());

  util::StatusOr<std::unique_ptr<ChunkedMacComputation>> computation =
      (*chunked_mac)->CreateComputation();
  ASSERT_THAT(computation, IsOk());
  ASSERT_THAT((*computation)->Update("abcxyz"), IsOk());
  util::StatusOr<std::string> tag = (*computation)->ComputeMac();
  ASSERT_THAT(tag, IsOk());

  util::StatusOr<std::unique_ptr<ChunkedMacVerification>> verification =
      (*chunked_mac)->CreateVerification(*tag);
  ASSERT_THAT(verification, IsOk());
  ASSERT_THAT((*verification)->Update("abc"), IsOk());
  EXPECT_THAT((*verification)->VerifyMac(),
              StatusIs(absl::StatusCode::kUnknown));
}

TEST(ChunkedMacTest, UpdateWrongOrderFails) {
  ASSERT_THAT(MacConfig::Register(), IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> key =
      KeysetHandle::GenerateNew(MacKeyTemplates::HmacSha256());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<std::unique_ptr<ChunkedMac>> chunked_mac =
      (*key)->GetPrimitive<ChunkedMac>();
  ASSERT_THAT(chunked_mac, IsOk());

  util::StatusOr<std::unique_ptr<ChunkedMacComputation>> computation =
      (*chunked_mac)->CreateComputation();
  ASSERT_THAT(computation, IsOk());
  ASSERT_THAT((*computation)->Update("abc"), IsOk());
  ASSERT_THAT((*computation)->Update("xyz"), IsOk());
  util::StatusOr<std::string> tag = (*computation)->ComputeMac();
  ASSERT_THAT(tag, IsOk());

  util::StatusOr<std::unique_ptr<ChunkedMacVerification>> verification =
      (*chunked_mac)->CreateVerification(*tag);
  ASSERT_THAT(verification, IsOk());
  ASSERT_THAT((*verification)->Update("xyz"), IsOk());
  ASSERT_THAT((*verification)->Update("abc"), IsOk());
  EXPECT_THAT((*verification)->VerifyMac(),
              StatusIs(absl::StatusCode::kUnknown));
}

TEST(ChunkedMacTest, OperationsFailAfterComputeVerifyMac) {
  ASSERT_THAT(MacConfig::Register(), IsOk());

  util::StatusOr<std::unique_ptr<KeysetHandle>> key =
      KeysetHandle::GenerateNew(MacKeyTemplates::HmacSha256());
  ASSERT_THAT(key, IsOk());

  util::StatusOr<std::unique_ptr<ChunkedMac>> chunked_mac =
      (*key)->GetPrimitive<ChunkedMac>();
  ASSERT_THAT(chunked_mac, IsOk());

  util::StatusOr<std::unique_ptr<ChunkedMacComputation>> computation =
      (*chunked_mac)->CreateComputation();
  ASSERT_THAT(computation, IsOk());
  ASSERT_THAT((*computation)->Update("abc"), IsOk());
  ASSERT_THAT((*computation)->Update("xyz"), IsOk());
  util::StatusOr<std::string> tag = (*computation)->ComputeMac();
  ASSERT_THAT(tag, IsOk());

  // ChunkedMacComputation has already been finalized.
  EXPECT_THAT((*computation)->Update("toolate"),
              StatusIs(absl::StatusCode::kFailedPrecondition));
  EXPECT_THAT((*computation)->ComputeMac().status(),
              StatusIs(absl::StatusCode::kFailedPrecondition));

  util::StatusOr<std::unique_ptr<ChunkedMacVerification>> verification =
      (*chunked_mac)->CreateVerification(*tag);
  ASSERT_THAT(verification, IsOk());
  ASSERT_THAT((*verification)->Update("abc"), IsOk());
  ASSERT_THAT((*verification)->Update("xyz"), IsOk());
  EXPECT_THAT((*verification)->VerifyMac(), IsOk());

  // ChunkedMacVerification has already been finalized.
  EXPECT_THAT((*verification)->Update("toolate"),
              StatusIs(absl::StatusCode::kUnknown));
  EXPECT_THAT((*verification)->VerifyMac(),
              StatusIs(absl::StatusCode::kUnknown));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
