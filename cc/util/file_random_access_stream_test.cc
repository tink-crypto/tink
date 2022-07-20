// Copyright 2019 Google Inc.
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

#include "tink/util/file_random_access_stream.h"

#include <string>
#include <thread>  // NOLINT(build/c++11)
#include <utility>

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/util/buffer.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace util {
namespace {

// Reads the entire 'ra_stream' in chunks of size 'chunk_size',
// until no more bytes can be read, and puts the read bytes into 'contents'.
// Returns the status of the last ra_stream->Next()-operation.
util::Status ReadAll(RandomAccessStream* ra_stream, int chunk_size,
                     std::string* contents) {
  contents->clear();
  auto buffer = std::move(Buffer::New(chunk_size).value());
  int64_t position = 0;
  auto status = ra_stream->PRead(position, chunk_size, buffer.get());
  while (status.ok()) {
    contents->append(buffer->get_mem_block(), buffer->size());
    position = contents->size();
    status = ra_stream->PRead(position, chunk_size, buffer.get());
  }
  if (status.code() == absl::StatusCode::kOutOfRange) {  // EOF
    EXPECT_EQ(0, buffer->size());
  }
  return status;
}

// Reads from 'ra_stream' a chunk of 'count' bytes starting offset 'position',
// and compares the read bytes to the corresponding bytes in 'file_contents'.
void ReadAndVerifyChunk(RandomAccessStream* ra_stream,
                        int64_t position,
                        int count,
                        absl::string_view file_contents) {
  SCOPED_TRACE(absl::StrCat("stream_size = ", file_contents.size(),
                            ", position = ", position,
                            ", count = ", count));
  auto buffer = std::move(Buffer::New(count).value());
  int stream_size = ra_stream->size().value();
  EXPECT_EQ(file_contents.size(), stream_size);
  auto status = ra_stream->PRead(position, count, buffer.get());
  EXPECT_TRUE(status.ok());
  int read_count = buffer->size();
  int expected_count = count;
  if (position + count > stream_size) {
    expected_count = stream_size - position;
  }
  EXPECT_EQ(expected_count, read_count);
  EXPECT_EQ(0, memcmp(&file_contents[position],
                      buffer->get_mem_block(), read_count));
}

TEST(FileRandomAccessStreamTest, ReadingStreams) {
  for (auto stream_size : {1, 10, 100, 1000, 10000, 1000000}) {
    SCOPED_TRACE(absl::StrCat("stream_size = ", stream_size));
    std::string file_contents;
    std::string filename = absl::StrCat(stream_size, "_reading_test.bin");
    int input_fd =
        test::GetTestFileDescriptor(filename, stream_size, &file_contents);
    EXPECT_EQ(stream_size, file_contents.size());
    auto ra_stream = absl::make_unique<util::FileRandomAccessStream>(input_fd);
    std::string stream_contents;
    auto status = ReadAll(ra_stream.get(), 1 + (stream_size / 10),
                          &stream_contents);
    EXPECT_EQ(absl::StatusCode::kOutOfRange, status.code());
    EXPECT_EQ("EOF", status.message());
    EXPECT_EQ(file_contents, stream_contents);
    EXPECT_EQ(stream_size, ra_stream->size().value());
  }
}

TEST(FileRandomAccessStreamTest, ReadingStreamsTillLastByte) {
  for (auto stream_size : {1, 10, 100, 1000, 10000}) {
    SCOPED_TRACE(absl::StrCat("stream_size = ", stream_size));
    std::string file_contents;
    std::string filename = absl::StrCat(stream_size, "_reading_test.bin");
    int input_fd =
        test::GetTestFileDescriptor(filename, stream_size, &file_contents);
    EXPECT_EQ(stream_size, file_contents.size());
    auto ra_stream = absl::make_unique<util::FileRandomAccessStream>(input_fd);
    auto buffer = std::move(Buffer::New(stream_size).value());

    // Read from the beginning till the last byte.
    auto status = ra_stream->PRead(/* position = */ 0,
                                   stream_size, buffer.get());
    EXPECT_TRUE(status.ok());
    EXPECT_EQ(stream_size, ra_stream->size().value());
    EXPECT_EQ(0, memcmp(&file_contents[0],
                        buffer->get_mem_block(), stream_size));
  }
}


TEST(FileRandomAccessStreamTest, ConcurrentReads) {
  for (auto stream_size : {100, 1000, 10000, 100000}) {
    std::string file_contents;
    std::string filename = absl::StrCat(stream_size, "_reading_test.bin");
    int input_fd =
        test::GetTestFileDescriptor(filename, stream_size, &file_contents);
    EXPECT_EQ(stream_size, file_contents.size());
    auto ra_stream = absl::make_unique<util::FileRandomAccessStream>(input_fd);
    std::thread read_0(ReadAndVerifyChunk,
        ra_stream.get(), 0, stream_size / 2, file_contents);
    std::thread read_1(ReadAndVerifyChunk,
        ra_stream.get(), stream_size / 4, stream_size / 2, file_contents);
    std::thread read_2(ReadAndVerifyChunk,
        ra_stream.get(), stream_size / 2, stream_size / 2, file_contents);
    std::thread read_3(ReadAndVerifyChunk,
        ra_stream.get(), 3 * stream_size / 4, stream_size / 2, file_contents);
    read_0.join();
    read_1.join();
    read_2.join();
    read_3.join();
  }
}

TEST(FileRandomAccessStreamTest, NegativeReadPosition) {
  for (auto stream_size : {0, 10, 100, 1000, 10000}) {
    std::string file_contents;
    std::string filename = absl::StrCat(stream_size, "_reading_test.bin");
    int input_fd =
        test::GetTestFileDescriptor(filename, stream_size, &file_contents);
    auto ra_stream = absl::make_unique<util::FileRandomAccessStream>(input_fd);
    int count = 42;
    auto buffer = std::move(Buffer::New(count).value());
    for (auto position : {-100, -10, -1}) {
      SCOPED_TRACE(absl::StrCat("stream_size = ", stream_size,
                                " position = ", position));

      auto status = ra_stream->PRead(position, count, buffer.get());
      EXPECT_EQ(absl::StatusCode::kInvalidArgument, status.code());
    }
  }
}

TEST(FileRandomAccessStreamTest, NotPositiveReadCount) {
  for (auto stream_size : {0, 10, 100, 1000, 10000}) {
    std::string file_contents;
    std::string filename = absl::StrCat(stream_size, "_reading_test.bin");
    int input_fd =
        test::GetTestFileDescriptor(filename, stream_size, &file_contents);
    auto ra_stream = absl::make_unique<util::FileRandomAccessStream>(input_fd);
    auto buffer = std::move(Buffer::New(42).value());
    int64_t position = 0;
    for (auto count : {-100, -10, -1, 0}) {
      SCOPED_TRACE(absl::StrCat("stream_size = ", stream_size,
                                " count = ", count));
      auto status = ra_stream->PRead(position, count, buffer.get());
      EXPECT_EQ(absl::StatusCode::kInvalidArgument, status.code());
    }
  }
}

TEST(FileRandomAccessStreamTest, ReadPositionAfterEof) {
  for (auto stream_size : {0, 10, 100, 1000, 10000}) {
    std::string file_contents;
    std::string filename = absl::StrCat(stream_size, "_reading_test.bin");
    int input_fd =
        test::GetTestFileDescriptor(filename, stream_size, &file_contents);
    auto ra_stream = absl::make_unique<util::FileRandomAccessStream>(input_fd);
    int count = 42;
    auto buffer = std::move(Buffer::New(count).value());
    for (auto position : {stream_size + 1, stream_size + 10}) {
      SCOPED_TRACE(absl::StrCat("stream_size = ", stream_size,
                                " position = ", position));

      auto status = ra_stream->PRead(position, count, buffer.get());
      EXPECT_EQ(absl::StatusCode::kOutOfRange, status.code());
      EXPECT_EQ(0, buffer->size());
    }
  }
}

}  // namespace
}  // namespace util
}  // namespace tink
}  // namespace crypto
