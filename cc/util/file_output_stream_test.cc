// Copyright 2018 Google Inc.
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

#include "tink/util/file_output_stream.h"

#include <algorithm>
#include <string>

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/subtle/random.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

// Writes 'contents' the specified 'output_stream', and closes the stream.
// Returns the status of output_stream->Close()-operation, or a non-OK status
// of a prior output_stream->Next()-operation, if any.
util::Status WriteToStream(util::FileOutputStream* output_stream,
                           absl::string_view contents) {
  void* buffer;
  int pos = 0;
  int remaining = contents.length();
  int available_space = 0;
  int available_bytes = 0;
  while (remaining > 0) {
    auto next_result = output_stream->Next(&buffer);
    if (!next_result.ok()) return next_result.status();
    available_space = next_result.value();
    available_bytes = std::min(available_space, remaining);
    memcpy(buffer, contents.data() + pos, available_bytes);
    remaining -= available_bytes;
    pos += available_bytes;
  }
  if (available_space > available_bytes) {
    output_stream->BackUp(available_space - available_bytes);
  }
  return output_stream->Close();
}

class FileOutputStreamTest : public ::testing::Test {
};

TEST_F(FileOutputStreamTest, WritingStreams) {
  for (auto stream_size : {0, 10, 100, 1000, 10000, 100000, 1000000}) {
    SCOPED_TRACE(absl::StrCat("stream_size = ", stream_size));
    std::string stream_contents = subtle::Random::GetRandomBytes(stream_size);
    std::string filename = absl::StrCat(stream_size, "_writing_test.bin");
    int output_fd = test::GetTestFileDescriptor(filename);
    auto output_stream = absl::make_unique<util::FileOutputStream>(output_fd);
    auto status = WriteToStream(output_stream.get(), stream_contents);
    EXPECT_TRUE(status.ok()) << status;
    std::string file_contents = test::ReadTestFile(filename);
    EXPECT_EQ(stream_size, file_contents.size());
    EXPECT_EQ(stream_contents, file_contents);
  }
}

TEST_F(FileOutputStreamTest, CustomBufferSizes) {
  int stream_size = 1024 * 1024;
  std::string stream_contents = subtle::Random::GetRandomBytes(stream_size);
  for (auto buffer_size : {1, 10, 100, 1000, 10000, 100000, 1000000}) {
    SCOPED_TRACE(absl::StrCat("buffer_size = ", buffer_size));
    std::string filename = absl::StrCat(buffer_size, "_buffer_size_test.bin");
    int output_fd = test::GetTestFileDescriptor(filename);
    auto output_stream =
        absl::make_unique<util::FileOutputStream>(output_fd, buffer_size);
    void* buffer;
    auto next_result = output_stream->Next(&buffer);
    EXPECT_TRUE(next_result.ok()) << next_result.status();
    EXPECT_EQ(buffer_size, next_result.value());
    output_stream->BackUp(buffer_size);
    auto status = WriteToStream(output_stream.get(), stream_contents);
    EXPECT_TRUE(status.ok()) << status;
    std::string file_contents = test::ReadTestFile(filename);
    EXPECT_EQ(stream_size, file_contents.size());
    EXPECT_EQ(stream_contents, file_contents);
  }
}


TEST_F(FileOutputStreamTest, BackupAndPosition) {
  int stream_size = 1024 * 1024;
  int buffer_size = 1234;
  void* buffer;
  std::string stream_contents = subtle::Random::GetRandomBytes(stream_size);
  std::string filename = absl::StrCat(buffer_size, "_backup_test.bin");
  int output_fd = test::GetTestFileDescriptor(filename);

  // Prepare the stream and do the first call to Next().
  auto output_stream =
      absl::make_unique<util::FileOutputStream>(output_fd, buffer_size);
  EXPECT_EQ(0, output_stream->Position());
  auto next_result = output_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.value());
  EXPECT_EQ(buffer_size, output_stream->Position());
  std::memcpy(buffer, stream_contents.data(), buffer_size);

  // BackUp several times, but in total fewer bytes than returned by Next().
  int total_backup_size = 0;
  for (auto backup_size : {0, 1, 5, 0, 10, 100, -42, 400, 20, -100}) {
    SCOPED_TRACE(absl::StrCat("backup_size = ", backup_size));
    output_stream->BackUp(backup_size);
    total_backup_size += std::max(0, backup_size);
    EXPECT_EQ(buffer_size - total_backup_size, output_stream->Position());
  }
  EXPECT_LT(total_backup_size, next_result.value());

  // Call Next(), it should succeed.
  next_result = output_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();

  // BackUp() some bytes, again fewer than returned by Next().
  total_backup_size = 0;
  for (auto backup_size : {0, 72, -94, 37, 82}) {
    SCOPED_TRACE(absl::StrCat("backup_size = ", backup_size));
    output_stream->BackUp(backup_size);
    total_backup_size += std::max(0, backup_size);
    EXPECT_EQ(buffer_size - total_backup_size, output_stream->Position());
  }
  EXPECT_LT(total_backup_size, next_result.value());

  // Call Next(), it should succeed;
  next_result = output_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();

  // Call Next() again, it should return a full block.
  auto prev_position = output_stream->Position();
  next_result = output_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.value());
  EXPECT_EQ(prev_position + buffer_size, output_stream->Position());
  std::memcpy(buffer, stream_contents.data() + buffer_size, buffer_size);

  // BackUp a few times, with total over the returned buffer_size.
  total_backup_size = 0;
  for (auto backup_size :
           {0, 72, -100, buffer_size / 2, 200, -25, buffer_size / 2, 42}) {
    SCOPED_TRACE(absl::StrCat("backup_size = ", backup_size));
    output_stream->BackUp(backup_size);
    total_backup_size = std::min(buffer_size,
                                 total_backup_size + std::max(0, backup_size));
    EXPECT_EQ(prev_position + buffer_size - total_backup_size,
              output_stream->Position());
  }
  EXPECT_EQ(total_backup_size, buffer_size);
  EXPECT_EQ(prev_position, output_stream->Position());

  // Call Next() again, it should return a full block.
  next_result = output_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.value());
  EXPECT_EQ(prev_position + buffer_size, output_stream->Position());
  std::memcpy(buffer, stream_contents.data() + buffer_size, buffer_size);

  // Write the remaining stream contents to stream.
  auto status = WriteToStream(
      output_stream.get(), stream_contents.substr(output_stream->Position()));
  EXPECT_TRUE(status.ok()) << status;
  std::string file_contents = test::ReadTestFile(filename);
  EXPECT_EQ(stream_size, file_contents.size());
  EXPECT_EQ(stream_contents, file_contents);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
