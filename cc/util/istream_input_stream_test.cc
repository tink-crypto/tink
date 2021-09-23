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

#include "tink/util/istream_input_stream.h"

#include <unistd.h>
#include <fstream>
#include <iostream>
#include <istream>

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "tink/subtle/random.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

// Creates a new test file with the specified 'filename', writes 'size' random
// bytes to the file, and returns an istream for reading from the file.
// A copy of the bytes written to the file is returned in 'file_contents'.
std::unique_ptr<std::istream> GetTestIstream(absl::string_view filename,
                                             int size,
                                             std::string* file_contents) {
  std::string full_filename =
      absl::StrCat(crypto::tink::test::TmpDir(), "/", filename);
  (*file_contents) = subtle::Random::GetRandomBytes(size);
  std::ofstream output (full_filename, std::ofstream::binary);
  if (!output.write(file_contents->data(), size) || output.tellp() != size) {
    std::clog << "Failed to write " << size << " bytes to file "
              << full_filename << " error: " << errno << std::endl;

    exit(1);
  }
  output.close();
  auto test_istream = absl::make_unique<std::ifstream>(
      full_filename, std::ofstream::binary);
  return std::move(test_istream);
}

// Reads the specified 'input_stream' until no more bytes can be read,
// and puts the read bytes into 'contents'.
// Returns the status of the last input_stream->Next()-operation.
util::Status ReadTillEnd(util::IstreamInputStream* input_stream,
                         std::string* contents) {
  contents->clear();
  const void* buffer;
  auto next_result = input_stream->Next(&buffer);
  while (next_result.ok()) {
    contents->append(static_cast<const char*>(buffer),
                     next_result.ValueOrDie());
    next_result = input_stream->Next(&buffer);
  }
  return next_result.status();
}

class IstreamInputStreamTest : public ::testing::Test {
};

TEST_F(IstreamInputStreamTest, testReadingStreams) {
  for (int stream_size : {0, 10, 100, 1000, 10000, 100000, 1000000}) {
    std::string file_contents;
    std::string filename = absl::StrCat(stream_size, "_reading_test.bin");
    auto input = GetTestIstream(filename, stream_size, &file_contents);
    EXPECT_EQ(stream_size, file_contents.size());
    auto input_stream = absl::make_unique<util::IstreamInputStream>(
        std::move(input));
    std::string stream_contents;
    auto status = ReadTillEnd(input_stream.get(), &stream_contents);
    EXPECT_EQ(absl::StatusCode::kOutOfRange, status.code());
    EXPECT_EQ("EOF", status.error_message());
    EXPECT_EQ(file_contents, stream_contents);
  }
}

TEST_F(IstreamInputStreamTest, testCustomBufferSizes) {
  int stream_size = 100000;
  for (int buffer_size : {1, 10, 100, 1000, 10000}) {
    std::string file_contents;
    std::string filename = absl::StrCat(buffer_size, "_buffer_size_test.bin");
    auto input = GetTestIstream(filename, stream_size, &file_contents);
    EXPECT_EQ(stream_size, file_contents.size());
    auto input_stream = absl::make_unique<util::IstreamInputStream>(
        std::move(input), buffer_size);
    const void* buffer;
    auto next_result = input_stream->Next(&buffer);
    EXPECT_TRUE(next_result.ok()) << next_result.status();
    EXPECT_EQ(buffer_size, next_result.ValueOrDie());
    EXPECT_EQ(file_contents.substr(0, buffer_size),
              std::string(static_cast<const char*>(buffer), buffer_size));
  }
}

TEST_F(IstreamInputStreamTest, testBackupAndPosition) {
  int stream_size = 100000;
  int buffer_size = 1234;
  const void* buffer;
  std::string file_contents;
  std::string filename = absl::StrCat(buffer_size, "_backup_test.bin");
  auto input = GetTestIstream(filename, stream_size, &file_contents);
  EXPECT_EQ(stream_size, file_contents.size());

  // Prepare the stream and do the first call to Next().
  auto input_stream = absl::make_unique<util::IstreamInputStream>(
      std::move(input), buffer_size);
  EXPECT_EQ(0, input_stream->Position());
  auto next_result = input_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.ValueOrDie());
  EXPECT_EQ(buffer_size, input_stream->Position());
  EXPECT_EQ(file_contents.substr(0, buffer_size),
            std::string(static_cast<const char*>(buffer), buffer_size));

  // BackUp several times, but in total fewer bytes than returned by Next().
  int total_backup_size = 0;
  for (auto backup_size : {0, 1, 5, 0, 10, 100, -42, 400, 20, -100}) {
    input_stream->BackUp(backup_size);
    total_backup_size += std::max(0, backup_size);
    EXPECT_EQ(buffer_size - total_backup_size, input_stream->Position());
  }
  // Call Next(), it should return exactly the backed up bytes.
  next_result = input_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(total_backup_size, next_result.ValueOrDie());
  EXPECT_EQ(buffer_size, input_stream->Position());
  EXPECT_EQ(
      file_contents.substr(buffer_size - total_backup_size, total_backup_size),
      std::string(static_cast<const char*>(buffer), total_backup_size));

  // BackUp() some bytes, again fewer than returned by Next().
  total_backup_size = 0;
  for (int backup_size : {0, 72, -94, 37, 82}) {
    input_stream->BackUp(backup_size);
    total_backup_size += std::max(0, backup_size);
    EXPECT_EQ(buffer_size - total_backup_size, input_stream->Position());
  }

  // Call Next(), it should return exactly the backed up bytes.
  next_result = input_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(total_backup_size, next_result.ValueOrDie());
  EXPECT_EQ(buffer_size, input_stream->Position());
  EXPECT_EQ(
      file_contents.substr(buffer_size - total_backup_size, total_backup_size),
      std::string(static_cast<const char*>(buffer), total_backup_size));

  // Call Next() again, it should return the second block.
  next_result = input_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.ValueOrDie());
  EXPECT_EQ(2 * buffer_size, input_stream->Position());
  EXPECT_EQ(file_contents.substr(buffer_size, buffer_size),
            std::string(static_cast<const char*>(buffer), buffer_size));

  // BackUp a few times, with total over the returned buffer_size.
  total_backup_size = 0;
  for (int backup_size :
           {0, 72, -100, buffer_size/2, 200, -25, buffer_size, 42}) {
    input_stream->BackUp(backup_size);
    total_backup_size = std::min(buffer_size,
                                 total_backup_size + std::max(0, backup_size));
    EXPECT_EQ(2 * buffer_size - total_backup_size, input_stream->Position());
  }

  // Call Next() again, it should return the second block.
  next_result = input_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.ValueOrDie());
  EXPECT_EQ(2 * buffer_size, input_stream->Position());
  EXPECT_EQ(file_contents.substr(buffer_size, buffer_size),
            std::string(static_cast<const char*>(buffer), buffer_size));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
