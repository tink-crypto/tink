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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {

namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::util::IstreamInputStream;
using ::testing::Eq;

TEST(ReadAtMostTest, Basic) {
  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("Some content")};
  auto text_or = ReadAtMostFromStream(100, &input_stream);
  ASSERT_THAT(text_or.status(), IsOk());
  EXPECT_THAT(text_or.ValueOrDie(), Eq("Some content"));
}

TEST(ReadAtMostTest, ReadLess) {
  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdefghijklmnop")};
  auto text_or = ReadAtMostFromStream(7, &input_stream);
  EXPECT_THAT(text_or.ValueOrDie(), Eq("0123456"));
}

TEST(ReadAtMostTest, ReadTwice) {
  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdefghijklmnop")};
  auto text_or = ReadAtMostFromStream(7, &input_stream);
  EXPECT_THAT(text_or.ValueOrDie(), Eq("0123456"));

  text_or = ReadAtMostFromStream(5, &input_stream);
  EXPECT_THAT(text_or.ValueOrDie(), Eq("789ab"));
}

TEST(ReadAtMostTest, ReadMoreThanBlockSize) {
  // Use a block size of 4 such that ReadAtMost has to call the input multiple
  // times.
  IstreamInputStream input_stream{
      absl::make_unique<std::stringstream>("0123456789abcdefghijklmnop"), 4};
  auto text_or = ReadAtMostFromStream(11, &input_stream);
  EXPECT_THAT(text_or.ValueOrDie(), Eq("0123456789a"));

  text_or = ReadAtMostFromStream(5, &input_stream);
  EXPECT_THAT(text_or.ValueOrDie(), Eq("bcdef"));
}

TEST(ReadAtMostTest, LessAvailable) {
  IstreamInputStream input_stream(
      absl::make_unique<std::stringstream>("0123456789"));
  auto text_or = ReadAtMostFromStream(16, &input_stream);
  EXPECT_THAT(text_or.ValueOrDie(), Eq("0123456789"));
}

TEST(ReadAtMostTest, Request0) {
  IstreamInputStream input_stream(
      absl::make_unique<std::stringstream>("012345678"));
  auto text_or = ReadAtMostFromStream(0, &input_stream);
  EXPECT_THAT(ReadAtMostFromStream(4, &input_stream).ValueOrDie(), Eq("0123"));
  EXPECT_THAT(ReadAtMostFromStream(0, &input_stream).ValueOrDie(), Eq(""));
  EXPECT_THAT(ReadAtMostFromStream(5, &input_stream).ValueOrDie(), Eq("45678"));
  EXPECT_THAT(ReadAtMostFromStream(0, &input_stream).ValueOrDie(), Eq(""));
}

TEST(ReadAtMostTest, RequestNegative) {
  IstreamInputStream input_stream(
      absl::make_unique<std::stringstream>("012345678"));
  EXPECT_THAT(ReadAtMostFromStream(-1, &input_stream).ValueOrDie(), Eq(""));
}

TEST(ReadAtMostTest, EmptyInput) {
  IstreamInputStream input_stream(
      absl::make_unique<std::stringstream>(""));
  EXPECT_THAT(ReadAtMostFromStream(0, &input_stream).ValueOrDie(), Eq(""));
  EXPECT_THAT(ReadAtMostFromStream(1, &input_stream).ValueOrDie(), Eq(""));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
