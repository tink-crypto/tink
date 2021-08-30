// Copyright 2020 Google LLC
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
#include "tink/subtle/prf/prf_set_util.h"

#include <functional>
#include <memory>
#include <sstream>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "tink/input_stream.h"
#include "tink/subtle/prf/streaming_prf.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::test::IsOk;
using ::testing::_;
using ::testing::AnyNumber;
using ::testing::DefaultValue;
using ::testing::Eq;
using ::testing::NiceMock;
using ::testing::Not;
using ::testing::Return;
using ::testing::StrEq;

class MockPrf : public Prf {
 public:
  MOCK_METHOD(util::StatusOr<std::string>, Compute,
              (absl::string_view input, size_t output_length), (const));
};

class MockStatefulMac : public StatefulMac {
 public:
  MOCK_METHOD(util::Status, Update, (absl::string_view data), (override));
  MOCK_METHOD(util::StatusOr<std::string>, Finalize, (), (override));
};

class FakeStatefulMacFactory : public StatefulMacFactory {
 public:
  FakeStatefulMacFactory(util::Status update_status,
                         util::StatusOr<std::string> finalize_result)
      : update_status_(update_status), finalize_result_(finalize_result) {}
  util::StatusOr<std::unique_ptr<StatefulMac>> Create() const override {
    auto mac_mock = absl::make_unique<NiceMock<MockStatefulMac>>();
    ON_CALL(*mac_mock, Update(_)).WillByDefault(Return(update_status_));
    ON_CALL(*mac_mock, Finalize()).WillByDefault(Return(finalize_result_));
    std::unique_ptr<StatefulMac> result = std::move(mac_mock);
    return std::move(result);
  }

 private:
  util::Status update_status_;
  util::StatusOr<std::string> finalize_result_;
};

class MockStreamingPrf : public StreamingPrf {
 public:
  MOCK_METHOD(std::unique_ptr<InputStream>, ComputePrf,
              (absl::string_view input), (const));
};

std::unique_ptr<InputStream> GetInputStreamForString(const std::string& input) {
  return absl::make_unique<util::IstreamInputStream>(
      absl::make_unique<std::stringstream>(input));
}

class PrfFromStatefulMacFactoryTest : public ::testing::Test {
 protected:
  void SetUpWithResult(util::Status update_status,
                       util::StatusOr<std::string> finalize_result) {
    prf_ = CreatePrfFromStatefulMacFactory(
        absl::make_unique<FakeStatefulMacFactory>(update_status,
                                                  finalize_result));
  }
  Prf* prf() { return prf_.get(); }

 private:
  std::unique_ptr<Prf> prf_;
};

TEST_F(PrfFromStatefulMacFactoryTest, ComputePrf) {
  SetUpWithResult(util::OkStatus(), std::string("mock_stateful_mac"));
  auto output_result = prf()->Compute("test_input", 5);
  ASSERT_TRUE(output_result.ok()) << output_result.status();
  EXPECT_THAT(output_result.ValueOrDie(), StrEq("mock_"));
}

TEST_F(PrfFromStatefulMacFactoryTest, ComputePrfUpdateFails) {
  SetUpWithResult(util::Status(util::error::INTERNAL, "UpdateFailed"),
                  std::string("mock_stateful_mac"));
  auto output_result = prf()->Compute("test_input", 5);
  EXPECT_FALSE(output_result.ok());
  EXPECT_THAT(output_result.status().error_message(), StrEq("UpdateFailed"));
}

TEST_F(PrfFromStatefulMacFactoryTest, ComputePrfFinalizeFails) {
  SetUpWithResult(util::OkStatus(),
                  util::Status(util::error::INTERNAL, "FinalizeFailed"));
  auto output_result = prf()->Compute("test_input", 5);
  EXPECT_FALSE(output_result.ok());
  EXPECT_THAT(output_result.status().error_message(), StrEq("FinalizeFailed"));
}

TEST_F(PrfFromStatefulMacFactoryTest, ComputePrfTooMuchOutputRequested) {
  SetUpWithResult(util::OkStatus(), std::string("mock_stateful_mac"));
  auto output_result = prf()->Compute("test_input", 100);
  EXPECT_FALSE(output_result.ok());
}

class PrfFromStreamingPrfTest : public ::testing::Test {
 protected:
  void SetUp() override {
    auto streaming_prf = absl::make_unique<NiceMock<MockStreamingPrf>>();
    DefaultValue<std::unique_ptr<InputStream>>::SetFactory(
        [] { return GetInputStreamForString("output"); });
    EXPECT_CALL(*streaming_prf, ComputePrf(Eq("input"))).Times(AnyNumber());
    prf_ = CreatePrfFromStreamingPrf(std::move(streaming_prf));
  }
  Prf* prf() { return prf_.get(); }

 private:
  std::unique_ptr<Prf> prf_;
};

TEST_F(PrfFromStreamingPrfTest, ComputePrfBasic) {
  auto output_result = prf()->Compute("input", 5);
  ASSERT_THAT(output_result.status(), IsOk());
  EXPECT_THAT(output_result.ValueOrDie(), StrEq("outpu"));
}

TEST_F(PrfFromStreamingPrfTest, ComputeTwice) {
  auto output_result = prf()->Compute("input", 5);
  ASSERT_THAT(output_result.status(), IsOk());
  EXPECT_THAT(output_result.ValueOrDie(), StrEq("outpu"));
  output_result = prf()->Compute("input", 5);
  ASSERT_THAT(output_result.status(), IsOk());
  EXPECT_THAT(output_result.ValueOrDie(), StrEq("outpu"));
}

TEST_F(PrfFromStreamingPrfTest, ComputeSubstring) {
  auto output_result = prf()->Compute("input", 5);
  ASSERT_THAT(output_result.status(), IsOk());
  EXPECT_THAT(output_result.ValueOrDie(), StrEq("outpu"));
  output_result = prf()->Compute("input", 6);
  ASSERT_THAT(output_result.status(), IsOk());
  EXPECT_THAT(output_result.ValueOrDie(), StrEq("output"));
  output_result = prf()->Compute("input", 2);
  ASSERT_THAT(output_result.status(), IsOk());
  EXPECT_THAT(output_result.ValueOrDie(), StrEq("ou"));
}

TEST_F(PrfFromStreamingPrfTest, ComputeTooMuch) {
  auto output_result = prf()->Compute("input", 5);
  ASSERT_THAT(output_result.status(), IsOk());
  EXPECT_THAT(output_result.ValueOrDie(), StrEq("outpu"));
  output_result = prf()->Compute("input", 100);
  EXPECT_THAT(output_result.status(), Not(IsOk()))
      << "Output should not be okay, too much output requested";
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
