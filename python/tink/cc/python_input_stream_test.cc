// Copyright 2020 Google LLC
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

#include "tink/cc/python_input_stream.h"

#include <algorithm>
#include <string>
#include <utility>

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/subtle/random.h"
#include "tink/cc/test_util.h"

namespace crypto {
namespace tink {
namespace {

// Reads the specified 'input_stream' until no more bytes can be read,
// and puts the read bytes into 'contents'.
// Returns the status of the last input_stream->Next()-operation.
util::Status ReadTillEnd(PythonInputStream* input_stream,
                         std::string* contents) {
  contents->clear();
  const void* buffer;
  auto next_result = input_stream->Next(&buffer);
  while (next_result.ok()) {
    contents->append(static_cast<const char*>(buffer), next_result.value());
    next_result = input_stream->Next(&buffer);
  }
  return next_result.status();
}

TEST(PythonInputStreamTest, testReadingStreams) {
  for (int stream_size : {0, 10, 100, 1000, 10000, 100000, 1000000}) {
    std::string contents = subtle::Random::GetRandomBytes(stream_size);
    auto input = absl::make_unique<test::TestReadableObject>(contents);
    EXPECT_EQ(stream_size, contents.size());
    auto input_stream = absl::make_unique<PythonInputStream>(std::move(input));
    std::string stream_contents;
    auto status = ReadTillEnd(input_stream.get(), &stream_contents);
    EXPECT_EQ(absl::StatusCode::kOutOfRange, status.code());
    EXPECT_EQ("EOF", status.message());
    EXPECT_EQ(contents, stream_contents);
  }
}

TEST(PythonInputStreamTest, testCustomBufferSizes) {
  int stream_size = 100000;
  for (int buffer_size : {1, 10, 100, 1000, 10000}) {
    std::string contents = subtle::Random::GetRandomBytes(stream_size);
    auto input = absl::make_unique<test::TestReadableObject>(contents);
    EXPECT_EQ(stream_size, contents.size());
    auto input_stream =
        absl::make_unique<PythonInputStream>(std::move(input), buffer_size);
    const void* buffer;
    auto next_result = input_stream->Next(&buffer);
    EXPECT_TRUE(next_result.ok()) << next_result.status();
    EXPECT_EQ(buffer_size, next_result.value());
    EXPECT_EQ(contents.substr(0, buffer_size),
              std::string(static_cast<const char*>(buffer), buffer_size));
  }
}

TEST(PythonInputStreamTest, testBackupAndPosition) {
  int stream_size = 100000;
  int buffer_size = 1234;
  const void* buffer;
  std::string contents = subtle::Random::GetRandomBytes(stream_size);
  auto input = absl::make_unique<test::TestReadableObject>(contents);
  EXPECT_EQ(stream_size, contents.size());

  // Prepare the stream and do the first call to Next().
  auto input_stream =
      absl::make_unique<PythonInputStream>(std::move(input), buffer_size);
  EXPECT_EQ(0, input_stream->Position());
  auto next_result = input_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.value());
  EXPECT_EQ(buffer_size, input_stream->Position());
  EXPECT_EQ(contents.substr(0, buffer_size),
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
  EXPECT_EQ(total_backup_size, next_result.value());
  EXPECT_EQ(buffer_size, input_stream->Position());
  EXPECT_EQ(contents.substr(buffer_size - total_backup_size, total_backup_size),
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
  EXPECT_EQ(total_backup_size, next_result.value());
  EXPECT_EQ(buffer_size, input_stream->Position());
  EXPECT_EQ(contents.substr(buffer_size - total_backup_size, total_backup_size),
            std::string(static_cast<const char*>(buffer), total_backup_size));

  // Call Next() again, it should return the second block.
  next_result = input_stream->Next(&buffer);
  EXPECT_TRUE(next_result.ok()) << next_result.status();
  EXPECT_EQ(buffer_size, next_result.value());
  EXPECT_EQ(2 * buffer_size, input_stream->Position());
  EXPECT_EQ(contents.substr(buffer_size, buffer_size),
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
  EXPECT_EQ(buffer_size, next_result.value());
  EXPECT_EQ(2 * buffer_size, input_stream->Position());
  EXPECT_EQ(contents.substr(buffer_size, buffer_size),
            std::string(static_cast<const char*>(buffer), buffer_size));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
