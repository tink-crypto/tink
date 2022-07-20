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

#include "tink/util/input_stream_util.h"

#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {

namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::crypto::tink::util::IstreamInputStream;
using ::testing::Eq;

TEST(ReadBytesTest, ReadExact) {
  const std::string content = "Some content";
  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>(content)};
  auto text_or = ReadBytesFromStream(content.size(), &input_stream);
  ASSERT_THAT(text_or, IsOk());
  std::string text = std::move(text_or).value();
  EXPECT_THAT(text, Eq(content));
}

TEST(ReadBytesTest, ShortRead) {
  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("Some content")};
  auto text_or = ReadBytesFromStream(100, &input_stream);
  EXPECT_THAT(text_or.status(), StatusIs(absl::StatusCode::kOutOfRange));
}

TEST(ReadBytesTest, ReadLess) {
  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdefghijklmnop")};
  auto text_or = ReadBytesFromStream(7, &input_stream);
  ASSERT_THAT(text_or, IsOk());
  EXPECT_THAT(text_or.value(), Eq("0123456"));
}

TEST(ReadBytesTest, ReadTwice) {
  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdefghijklmnop")};
  auto text_or = ReadBytesFromStream(7, &input_stream);
  ASSERT_THAT(text_or, IsOk());
  EXPECT_THAT(text_or.value(), Eq("0123456"));

  text_or = ReadBytesFromStream(5, &input_stream);
  ASSERT_THAT(text_or, IsOk());
  EXPECT_THAT(text_or.value(), Eq("789ab"));
}

TEST(ReadBytesTest, ReadMoreThanBlockSize) {
  // Use a block size of 4 such that ReadAtMost has to call the input multiple
  // times.
  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdefghijklmnop"), 4};
  auto text_or = ReadBytesFromStream(11, &input_stream);
  ASSERT_THAT(text_or, IsOk());
  EXPECT_THAT(text_or.value(), Eq("0123456789a"));

  text_or = ReadBytesFromStream(5, &input_stream);
  ASSERT_THAT(text_or, IsOk());
  EXPECT_THAT(text_or.value(), Eq("bcdef"));
}

TEST(ReadBytesTest, Request0) {
  IstreamInputStream input_stream(
      absl::make_unique<std::stringstream>("012345678"));
  auto text_or = ReadBytesFromStream(4, &input_stream);
  ASSERT_THAT(text_or, IsOk());
  EXPECT_THAT(text_or.value(), Eq("0123"));
  text_or = ReadBytesFromStream(0, &input_stream);
  ASSERT_THAT(text_or, IsOk());
  EXPECT_THAT(text_or.value(), Eq(""));
  text_or = ReadBytesFromStream(5, &input_stream);
  ASSERT_THAT(text_or, IsOk());
  EXPECT_THAT(text_or.value(), Eq("45678"));
  text_or = ReadBytesFromStream(0, &input_stream);
  ASSERT_THAT(text_or, IsOk());
  EXPECT_THAT(text_or.value(), Eq(""));
}

TEST(ReadBytesTest, RequestNegative) {
  IstreamInputStream input_stream(
      absl::make_unique<std::stringstream>("012345678"));
  auto text_or = ReadBytesFromStream(-1, &input_stream);
  ASSERT_THAT(text_or, IsOk());
  EXPECT_THAT(text_or.value(), Eq(""));
}

TEST(ReadBytesTest, EmptyInput) {
  IstreamInputStream input_stream(absl::make_unique<std::stringstream>(""));
  auto text_or = ReadBytesFromStream(0, &input_stream);
  ASSERT_THAT(text_or, IsOk());
  EXPECT_THAT(text_or.value(), Eq(""));
  text_or = ReadBytesFromStream(1, &input_stream);
  EXPECT_THAT(text_or.status(), StatusIs(absl::StatusCode::kOutOfRange));
}

TEST(ReadSecretBytesTest, ReadExact) {
  const std::string content = "Some content";
  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>(content)};
  auto text_or = ReadSecretBytesFromStream(content.size(), &input_stream);
  ASSERT_THAT(text_or, IsOk());
  std::string text(util::SecretDataAsStringView(std::move(text_or).value()));
  EXPECT_THAT(text, Eq(content));
}

TEST(ReadSecretBytesTest, ShortRead) {
  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("Some content")};
  auto text_or = ReadSecretBytesFromStream(100, &input_stream);
  EXPECT_THAT(text_or.status(), StatusIs(absl::StatusCode::kOutOfRange));
}

TEST(ReadSecretBytesTest, ReadLess) {
  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdefghijklmnop")};
  auto text_or = ReadSecretBytesFromStream(7, &input_stream);
  ASSERT_THAT(text_or, IsOk());
  std::string text(util::SecretDataAsStringView(std::move(text_or).value()));
  EXPECT_THAT(text, Eq("0123456"));
}

TEST(ReadSecretBytesTest, ReadTwice) {
  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdefghijklmnop")};
  auto text_or = ReadSecretBytesFromStream(7, &input_stream);
  std::string text(util::SecretDataAsStringView(std::move(text_or).value()));
  EXPECT_THAT(text, Eq("0123456"));

  text_or = ReadSecretBytesFromStream(5, &input_stream);
  ASSERT_THAT(text_or, IsOk());
  text = std::string(util::SecretDataAsStringView(std::move(text_or).value()));
  EXPECT_THAT(text, Eq("789ab"));
}

TEST(ReadSecretBytesTest, ReadMoreThanBlockSize) {
  // Use a block size of 4 such that ReadAtMost has to call the input multiple
  // times.
  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdefghijklmnop"), 4};
  auto text_or = ReadSecretBytesFromStream(11, &input_stream);
  ASSERT_THAT(text_or, IsOk());
  std::string text(util::SecretDataAsStringView(std::move(text_or).value()));
  EXPECT_THAT(text, Eq("0123456789a"));

  text_or = ReadSecretBytesFromStream(5, &input_stream);
  ASSERT_THAT(text_or, IsOk());
  text = std::string(util::SecretDataAsStringView(std::move(text_or).value()));
  EXPECT_THAT(text, Eq("bcdef"));
}

TEST(ReadSecretBytesTest, Request0) {
  IstreamInputStream input_stream(
      absl::make_unique<std::stringstream>("012345678"));
  auto text_or = ReadSecretBytesFromStream(4, &input_stream);
  ASSERT_THAT(text_or, IsOk());
  std::string text(util::SecretDataAsStringView(std::move(text_or).value()));
  EXPECT_THAT(text, Eq("0123"));
  text_or = ReadSecretBytesFromStream(0, &input_stream);
  ASSERT_THAT(text_or, IsOk());
  text = std::string(util::SecretDataAsStringView(std::move(text_or).value()));
  EXPECT_THAT(text, Eq(""));
  text_or = ReadSecretBytesFromStream(5, &input_stream);
  ASSERT_THAT(text_or, IsOk());
  text = std::string(util::SecretDataAsStringView(std::move(text_or).value()));
  EXPECT_THAT(text, Eq("45678"));
  text_or = ReadSecretBytesFromStream(0, &input_stream);
  ASSERT_THAT(text_or, IsOk());
  text = std::string(util::SecretDataAsStringView(std::move(text_or).value()));
  EXPECT_THAT(text, Eq(""));
}

TEST(ReadSecretBytesTest, RequestNegative) {
  IstreamInputStream input_stream(
      absl::make_unique<std::stringstream>("012345678"));
  auto text_or = ReadSecretBytesFromStream(-1, &input_stream);
  ASSERT_THAT(text_or, IsOk());
  std::string text(util::SecretDataAsStringView(std::move(text_or).value()));
  EXPECT_THAT(text, Eq(""));
}

TEST(ReadSecretBytesTest, EmptyInput) {
  IstreamInputStream input_stream(
      absl::make_unique<std::stringstream>(""));
  auto text_or = ReadSecretBytesFromStream(0, &input_stream);
  ASSERT_THAT(text_or, IsOk());
  std::string text(util::SecretDataAsStringView(std::move(text_or).value()));
  EXPECT_THAT(text, Eq(""));
  text_or = ReadSecretBytesFromStream(1, &input_stream);
  EXPECT_THAT(text_or.status(), StatusIs(absl::StatusCode::kOutOfRange));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
