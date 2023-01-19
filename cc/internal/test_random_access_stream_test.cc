// Copyright 2023 Google LLC
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
#include "tink/internal/test_random_access_stream.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/subtle/random.h"
#include "tink/util/buffer.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::StatusIs;

TEST(TestRandomAccessStreamTest, ReadAllSucceeds) {
  const int buffer_size = 4 * 1024;
  const int stream_size = 100 * 1024;
  std::string stream_content = subtle::Random::GetRandomBytes(stream_size);
  auto rand_access_stream =
      std::make_unique<TestRandomAccessStream>(stream_content);
  auto buffer = *std::move(util::Buffer::New(buffer_size));
  util::Status pread_status = util::OkStatus();
  std::string result;
  do {
    pread_status =
        rand_access_stream->PRead(result.size(), buffer_size, buffer.get());
    result.append(buffer->get_mem_block(), buffer->size());
  } while (pread_status.ok());
  EXPECT_THAT(pread_status, StatusIs(absl::StatusCode::kOutOfRange));
  EXPECT_EQ(result, stream_content);
}

TEST(TestRandomAccessStreamTest, PreadAllInOnePread) {
  const int stream_size = 8 * 1024;
  std::string stream_content = subtle::Random::GetRandomBytes(stream_size);
  auto rand_access_stream =
      std::make_unique<TestRandomAccessStream>(stream_content);
  auto buffer = *std::move(util::Buffer::New(stream_size));
  ASSERT_THAT(
      rand_access_stream->PRead(/*position=*/0, stream_size, buffer.get()),
      StatusIs(absl::StatusCode::kOutOfRange));
  EXPECT_EQ(std::string(buffer->get_mem_block(), buffer->size()),
            stream_content);
}

TEST(TestRandomAccessStreamTest, PreadCountLargerThanBufferFails) {
  const int buffer_size = 4 * 1024;
  const int stream_size = 100 * 1024;
  std::string stream_content = subtle::Random::GetRandomBytes(stream_size);
  auto rand_access_stream =
      std::make_unique<TestRandomAccessStream>(stream_content);
  auto buffer = *std::move(util::Buffer::New(buffer_size));
  EXPECT_THAT(
      rand_access_stream->PRead(/*position=*/0, buffer_size + 1, buffer.get()),
      StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TestRandomAccessStreamTest, InvalidPosition) {
  const int buffer_size = 4 * 1024;
  const int stream_size = 100 * 1024;
  std::string stream_content = subtle::Random::GetRandomBytes(stream_size);
  auto rand_access_stream =
      std::make_unique<TestRandomAccessStream>(stream_content);
  auto buffer = *std::move(util::Buffer::New(buffer_size));
  EXPECT_THAT(rand_access_stream->PRead(-1, buffer_size, buffer.get()),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TestRandomAccessStreamTest, PreadWithNullBufferFails) {
  const int stream_size = 100 * 1024;
  std::string stream_content = subtle::Random::GetRandomBytes(stream_size);
  auto rand_access_stream =
      std::make_unique<TestRandomAccessStream>(stream_content);
  EXPECT_THAT(rand_access_stream->PRead(/*position=*/0, stream_size,
                                        /*dest_buffer=*/nullptr),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(TestRandomAccessStreamTest, PreadWithEmptyStreamEof) {
  const int buffer_size = 4 * 1024;
  std::string stream_content;  // Empty string.
  auto rand_access_stream =
      std::make_unique<TestRandomAccessStream>(stream_content);
  auto buffer = *std::move(util::Buffer::New(buffer_size));
  EXPECT_THAT(
      rand_access_stream->PRead(/*position=*/0, buffer_size, buffer.get()),
      StatusIs(absl::StatusCode::kOutOfRange));
}

// Pread of the last partial block populates the buffer with the remaining
// bytes and returns an EOF status.
TEST(TestRandomAccessStreamTest, PreadTheLastPartialBlockReturnsEof) {
  const int buffer_size = 4 * 1024;
  const int stream_size = 100 * 1024;
  std::string stream_content = subtle::Random::GetRandomBytes(stream_size);
  auto rand_access_stream =
      std::make_unique<TestRandomAccessStream>(stream_content);
  auto buffer = *std::move(util::Buffer::New(buffer_size));
  // Read at a postion so that only buffer_size - 1 bytes are left.
  EXPECT_THAT(rand_access_stream->PRead(stream_size - buffer_size + 1,
                                        buffer_size, buffer.get()),
              StatusIs(absl::StatusCode::kOutOfRange));
  EXPECT_EQ(buffer->size(), buffer_size - 1);
  EXPECT_EQ(std::string(buffer->get_mem_block(), buffer->size()),
            stream_content.substr(stream_size - buffer_size + 1));
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
