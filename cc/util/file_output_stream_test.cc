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

#include <fcntl.h>
#include <unistd.h>
#include <vector>

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "tink/subtle/random.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

// Creates a new test file with the specified 'filename', ready for writing.
int GetTestFileDescriptor(absl::string_view filename) {
  std::string full_filename =
      absl::StrCat(crypto::tink::test::TmpDir(), "/", filename);
  mode_t mode = S_IWUSR | S_IRUSR | S_IRGRP | S_IROTH;
  int fd = open(full_filename.c_str(), O_WRONLY | O_CREAT | O_TRUNC, mode);
  if (fd == -1) {
    std::clog << "Cannot create file " << full_filename
              << " error: " << errno << std::endl;
    exit(1);
  }
  return fd;
}

// Writes 'contents' the specified 'output_stream', and closes the stream.
// Returns the status of output_stream->Close()-operation, or a non-OK status
// of a prior output_stream->Next()-operation, if any.
util::Status WriteToStream(util::FileOutputStream* output_stream,
                           absl::string_view contents) {
  void* buffer;
  int pos = 0;
  int remaining = contents.length();
  int available_space;
  int available_bytes;
  while (remaining > 0) {
    auto next_result = output_stream->Next(&buffer);
    if (!next_result.ok()) return next_result.status();
    available_space = next_result.ValueOrDie();
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

// Reads the test file specified by 'filename', and returns its contents.
std::string ReadFile(std::string filename) {
  std::string full_filename =
      absl::StrCat(crypto::tink::test::TmpDir(), "/", filename);
  int fd = open(full_filename.c_str(), O_RDONLY);
  if (fd == -1) {
    std::clog << "Cannot open file " << full_filename
              << " error: " << errno << std::endl;
    exit(1);
  }
  std::string contents;
  int buffer_size = 128 * 1024;
  auto buffer = absl::make_unique<uint8_t[]>(buffer_size);
  int read_result = read(fd, buffer.get(), buffer_size);
  while (read_result > 0) {
    std::clog << "Read " << read_result << " bytes" << std::endl;
    contents.append(reinterpret_cast<const char*>(buffer.get()), read_result);
    read_result = read(fd, buffer.get(), buffer_size);
  }
  if (read_result < 0) {
    std::clog << "Error reading file " << full_filename
              << " error: " << errno << std::endl;
    exit(1);
  }
  close(fd);
  std::clog << "Read in total " << contents.length() << " bytes" << std::endl;
  return contents;
}

class FileOutputStreamTest : public ::testing::Test {
};

TEST_F(FileOutputStreamTest, WritingStreams) {
  std::vector<int> stream_sizes = {0, 10, 100, 1000, 10000, 100000, 1000000};
  for (auto stream_size : stream_sizes) {
    std::string stream_contents = subtle::Random::GetRandomBytes(stream_size);
    std::string filename = absl::StrCat(stream_size, "_writing_test.bin");
    int output_fd = GetTestFileDescriptor(filename);
    auto output_stream = absl::make_unique<util::FileOutputStream>(output_fd);
    auto status = WriteToStream(output_stream.get(), stream_contents);
    EXPECT_TRUE(status.ok()) << status;
    std::string file_contents = ReadFile(filename);
    EXPECT_EQ(stream_size, file_contents.size());
    EXPECT_EQ(stream_contents, file_contents);
  }
}

TEST_F(FileOutputStreamTest, CustomBufferSizes) {
  std::vector<int> buffer_sizes = {1, 10, 100, 1000, 10000, 100000, 1000000};
  int stream_size = 1024 * 1024;
  std::string stream_contents = subtle::Random::GetRandomBytes(stream_size);
  for (auto buffer_size : buffer_sizes) {
    std::string filename = absl::StrCat(buffer_size, "_buffer_size_test.bin");
    int output_fd = GetTestFileDescriptor(filename);
    auto output_stream =
        absl::make_unique<util::FileOutputStream>(output_fd, buffer_size);
    void* buffer;
    auto next_result = output_stream->Next(&buffer);
    EXPECT_TRUE(next_result.ok()) << next_result.status();
    EXPECT_EQ(buffer_size, next_result.ValueOrDie());
    output_stream->BackUp(buffer_size);
    auto status = WriteToStream(output_stream.get(), stream_contents);
    EXPECT_TRUE(status.ok()) << status;
    std::string file_contents = ReadFile(filename);
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
  int output_fd = GetTestFileDescriptor(filename);

  // Prepare the stream and do the first call to Next().
  auto output_stream =
      absl::make_unique<util::FileOutputStream>(output_fd, buffer_size);
  EXPECT_EQ(0, output_stream->Position());
  auto next_result = output_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.ValueOrDie());
  EXPECT_EQ(buffer_size, output_stream->Position());
  std::memcpy(buffer, stream_contents.data(), buffer_size);

  // BackUp several times, but in total fewer bytes than returned by Next().
  std::vector<int> backup_sizes = {0, 1, 5, 0, 10, 100, -42, 400, 20, -100};
  int total_backup_size = 0;
  for (auto backup_size : backup_sizes) {
    output_stream->BackUp(backup_size);
    total_backup_size += std::max(0, backup_size);
    EXPECT_EQ(buffer_size - total_backup_size, output_stream->Position());
  }
  EXPECT_LT(total_backup_size, next_result.ValueOrDie());

  // Call Next(), it should succeed.
  next_result = output_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();

  // BackUp() some bytes, again fewer than returned by Next().
  backup_sizes = {0, 72, -94, 37, 82};
  total_backup_size = 0;
  for (auto backup_size : backup_sizes) {
    output_stream->BackUp(backup_size);
    total_backup_size += std::max(0, backup_size);
    EXPECT_EQ(buffer_size - total_backup_size, output_stream->Position());
  }
  EXPECT_LT(total_backup_size, next_result.ValueOrDie());

  // Call Next(), it should succeed;
  next_result = output_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();

  // Call Next() again, it should return a full block.
  auto prev_position = output_stream->Position();
  next_result = output_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.ValueOrDie());
  EXPECT_EQ(prev_position + buffer_size, output_stream->Position());
  std::memcpy(buffer, stream_contents.data() + buffer_size, buffer_size);

  // BackUp a few times, with total over the returned buffer_size.
  backup_sizes = {0, 72, -100, buffer_size / 2, 200, -25, buffer_size / 2, 42};
  total_backup_size = 0;
  for (auto backup_size : backup_sizes) {
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
  EXPECT_EQ(buffer_size, next_result.ValueOrDie());
  EXPECT_EQ(prev_position + buffer_size, output_stream->Position());
  std::memcpy(buffer, stream_contents.data() + buffer_size, buffer_size);

  // Write the remaining stream contents to stream.
  auto status = WriteToStream(
      output_stream.get(), stream_contents.substr(output_stream->Position()));
  EXPECT_TRUE(status.ok()) << status;
  std::string file_contents = ReadFile(filename);
  EXPECT_EQ(stream_size, file_contents.size());
  EXPECT_EQ(stream_contents, file_contents);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
