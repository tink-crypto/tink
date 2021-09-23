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

#include "tink/streamingaead/buffered_input_stream.h"

#include <sstream>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/input_stream.h"
#include "tink/subtle/random.h"
#include "tink/subtle/test_util.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace streamingaead {
namespace {

using crypto::tink::test::IsOk;
using crypto::tink::test::StatusIs;
using subtle::test::ReadFromStream;
using testing::HasSubstr;


static int kBufferSize = 4096;

// Creates an InputStream with the specified contents.
std::unique_ptr<InputStream> GetInputStream(absl::string_view contents) {
  // Prepare ciphertext source stream.
  auto string_stream =
      absl::make_unique<std::stringstream>(std::string(contents));
  std::unique_ptr<InputStream> input_stream(
      absl::make_unique<util::IstreamInputStream>(
          std::move(string_stream), kBufferSize));
  return input_stream;
}

// Attempts to read 'count' bytes from 'input_stream', and writes the read
// bytes to 'output'.
util::Status ReadFromStream(InputStream* input_stream, int count,
                            std::string* output) {
  if (input_stream == nullptr || output == nullptr || count < 0) {
    return util::Status(util::error::INTERNAL, "Illegal read from a stream");
  }
  const void* buffer;
  output->clear();
  int bytes_to_read = count;
  while (bytes_to_read > 0) {
    auto next_result = input_stream->Next(&buffer);
    if (next_result.status().error_code() == util::error::OUT_OF_RANGE) {
      // End of stream.
      return util::OkStatus();
    }
    if (!next_result.ok()) return next_result.status();
    auto read_bytes = next_result.ValueOrDie();
    auto used_bytes = std::min(read_bytes, bytes_to_read);
    if (used_bytes > 0) {
      output->append(
          std::string(reinterpret_cast<const char*>(buffer), used_bytes));
      bytes_to_read -= used_bytes;
      if (bytes_to_read == 0) input_stream->BackUp(read_bytes - used_bytes);
    }
  }
  return util::OkStatus();
}

TEST(BufferedInputStreamTest, ReadingAndRewinding) {
  for (auto input_size : {0, 1, 10, 100, 1000, 10000, 100000}) {
    std::string contents = subtle::Random::GetRandomBytes(input_size);
    auto input_stream = GetInputStream(contents);
    auto buf_stream = absl::make_unique<BufferedInputStream>(
        std::move(input_stream));
    for (auto read_size : {0, 1, 10, 123, 300}) {
      SCOPED_TRACE(absl::StrCat("input_size = ", input_size,
                                ", read_size = ", read_size));
      // Read a prefix of the stream.
      std::string prefix;
      auto status = ReadFromStream(buf_stream.get(), read_size, &prefix);
      EXPECT_THAT(status, IsOk());
      EXPECT_EQ(std::min(read_size, input_size), buf_stream->Position());
      EXPECT_EQ(contents.substr(0, read_size), prefix);

      // Read the rest of the stream.
      std::string rest;
      status = ReadFromStream(buf_stream.get(), &rest);
      EXPECT_THAT(status, IsOk());
      EXPECT_EQ(input_size, buf_stream->Position());
      EXPECT_EQ(contents, prefix + rest);

      // Try reading again, should get an empty string.
      status = ReadFromStream(buf_stream.get(), &rest);
      EXPECT_THAT(status, IsOk());
      EXPECT_EQ("", rest);

      // Rewind and read again, again in two parts.
      status = buf_stream->Rewind();
      EXPECT_EQ(0, buf_stream->Position());
      EXPECT_THAT(status, IsOk());
      status = ReadFromStream(buf_stream.get(), read_size, &prefix);
      EXPECT_THAT(status, IsOk());
      EXPECT_EQ(std::min(read_size, input_size), buf_stream->Position());
      EXPECT_EQ(contents.substr(0, read_size), prefix);
      status = ReadFromStream(buf_stream.get(), &rest);
      EXPECT_THAT(status, IsOk());
      EXPECT_EQ(input_size, buf_stream->Position());
      EXPECT_EQ(contents, prefix + rest);

      // Rewind so that the next read iteration starts from the beginning.
      status = buf_stream->Rewind();
      EXPECT_THAT(status, IsOk());
      EXPECT_EQ(0, buf_stream->Position());
    }
  }
}

TEST(BufferedInputStreamTest, SingleBackup) {
  for (auto input_size : {0, 1, 10, 100, 1000, 10000, 100000}) {
    std::string contents = subtle::Random::GetRandomBytes(input_size);
    for (auto read_size : {0, 1, 10, 123, 300, 1024}) {
      SCOPED_TRACE(absl::StrCat("input_size = ", input_size,
                                ", read_size = ", read_size));
      auto input_stream = GetInputStream(contents);
      auto buf_stream = absl::make_unique<BufferedInputStream>(
          std::move(input_stream));

      // Read a part of the stream.
      std::string prefix;
      auto status = ReadFromStream(buf_stream.get(), read_size, &prefix);
      EXPECT_THAT(status, IsOk());
      EXPECT_EQ(std::min(read_size, input_size), buf_stream->Position());
      EXPECT_EQ(contents.substr(0, read_size), prefix);

      // Read the next block of the stream, and then back it up.
      const void* buf;
      int pos = buf_stream->Position();
      auto next_result = buf_stream->Next(&buf);
      if (read_size < input_size) {
        EXPECT_THAT(next_result.status(), IsOk());
        auto next_size = next_result.ValueOrDie();
        EXPECT_LE(next_size, kBufferSize);
        EXPECT_EQ(pos + next_size, buf_stream->Position());
        buf_stream->BackUp(next_size);
        EXPECT_EQ(pos, buf_stream->Position());
        buf_stream->BackUp(input_size);
        EXPECT_EQ(pos, buf_stream->Position());
      } else {
        EXPECT_EQ(absl::StatusCode::kOutOfRange, next_result.status().code());
      }

      // Read the rest of the input.
      std::string rest;
      status = ReadFromStream(buf_stream.get(), &rest);
      EXPECT_THAT(status, IsOk());
      EXPECT_EQ(input_size, buf_stream->Position());
      EXPECT_EQ(contents, prefix + rest);

      // Rewind and read prefix again.
      status = buf_stream->Rewind();
      EXPECT_EQ(0, buf_stream->Position());
      EXPECT_THAT(status, IsOk());
      status = ReadFromStream(buf_stream.get(), read_size, &prefix);
      EXPECT_THAT(status, IsOk());
      EXPECT_EQ(std::min(read_size, input_size), buf_stream->Position());
      EXPECT_EQ(contents.substr(0, read_size), prefix);

      // The next buffer should contain the rest of the input, if any.
      pos = buf_stream->Position();
      next_result = buf_stream->Next(&buf);
      if (read_size < input_size) {
        EXPECT_THAT(next_result.status(), IsOk());
        auto next_size = next_result.ValueOrDie();
        EXPECT_EQ(input_size - pos, next_size);
        EXPECT_EQ(input_size, buf_stream->Position());
        buf_stream->BackUp(next_size);
        EXPECT_EQ(pos, buf_stream->Position());
        buf_stream->BackUp(input_size);
        EXPECT_EQ(pos, buf_stream->Position());
      } else {
        EXPECT_EQ(absl::StatusCode::kOutOfRange, next_result.status().code());
      }

      // Read the rest of the input.
      status = ReadFromStream(buf_stream.get(), &rest);
      EXPECT_THAT(status, IsOk());
      EXPECT_EQ(input_size, buf_stream->Position());
      EXPECT_EQ(contents, prefix + rest);
    }
  }
}

TEST(BufferedInputStreamTest, MultipleBackups) {
  int input_size = 70000;
  std::string contents = subtle::Random::GetRandomBytes(input_size);
  auto input_stream = GetInputStream(contents);
  auto buf_stream = absl::make_unique<BufferedInputStream>(
      std::move(input_stream));
  const void* buffer;

  EXPECT_EQ(0, buf_stream->Position());
  auto next_result = buf_stream->Next(&buffer);
  EXPECT_THAT(next_result.status(), IsOk());
  auto next_size = next_result.ValueOrDie();
  EXPECT_EQ(contents.substr(0, next_size),
            std::string(static_cast<const char*>(buffer), next_size));

  // BackUp several times, but in total fewer bytes than returned by Next().
  int total_backup_size = 0;
  for (auto backup_size : {0, 1, 5, 0, 10, 100, -42, 400, 20, -100}) {
    buf_stream->BackUp(backup_size);
    total_backup_size += std::max(0, backup_size);
    EXPECT_EQ(next_size - total_backup_size, buf_stream->Position());
  }
  EXPECT_GT(next_size, total_backup_size);

  // Call Next(), it should return exactly the backed up bytes.
  next_result = buf_stream->Next(&buffer);
  EXPECT_THAT(next_result.status(), IsOk());
  EXPECT_EQ(total_backup_size, next_result.ValueOrDie());
  EXPECT_EQ(next_size, buf_stream->Position());
  EXPECT_EQ(contents.substr(next_size - total_backup_size, total_backup_size),
            std::string(static_cast<const char*>(buffer), total_backup_size));
}

TEST(BufferedInputStreamTest, DisableRewindingInitially) {
  for (auto input_size : {0, 10, 100, 1000, 10000}) {
    std::string contents = subtle::Random::GetRandomBytes(input_size);
    for (auto read_size : {0, 1, 10, 123, 300, 1024}) {
      SCOPED_TRACE(absl::StrCat("input_size = ", input_size,
                                ", read_size = ", read_size));
      auto input_stream = GetInputStream(contents);
      auto buf_stream = absl::make_unique<BufferedInputStream>(
          std::move(input_stream));

      // Disable rewinding, and attempt rewind.
      EXPECT_EQ(0, buf_stream->Position());
      buf_stream->DisableRewinding();
      auto status = buf_stream->Rewind();
      EXPECT_THAT(status, StatusIs(util::error::INVALID_ARGUMENT,
                                   HasSubstr("rewinding is disabled")));

      // Read a prefix of the stream.
      std::string prefix;
      status = ReadFromStream(buf_stream.get(), read_size, &prefix);
      EXPECT_THAT(status, IsOk());
      EXPECT_EQ(std::min(read_size, input_size), buf_stream->Position());
      EXPECT_EQ(contents.substr(0, read_size), prefix);

      // Attempt rewidning again.
      status = buf_stream->Rewind();
      EXPECT_THAT(status, StatusIs(util::error::INVALID_ARGUMENT,
                                   HasSubstr("rewinding is disabled")));

      // Read the rest of the input.
      std::string rest;
      status = ReadFromStream(buf_stream.get(), &rest);
      EXPECT_THAT(status, IsOk());
      EXPECT_EQ(input_size, buf_stream->Position());
      EXPECT_EQ(contents, prefix + rest);
    }
  }
}

TEST(BufferedInputStreamTest, DisableRewindingAfterRewind) {
  for (auto input_size : {0, 10, 100, 1000, 10000}) {
    std::string contents = subtle::Random::GetRandomBytes(input_size);
    for (auto read_size : {0, 1, 10, 123, 300, 1024}) {
      SCOPED_TRACE(absl::StrCat("input_size = ", input_size,
                                ", read_size = ", read_size));
      auto input_stream = GetInputStream(contents);
      auto buf_stream = absl::make_unique<BufferedInputStream>(
          std::move(input_stream));

      // Read a prefix of the stream.
      std::string prefix;
      auto status = ReadFromStream(buf_stream.get(), read_size, &prefix);
      EXPECT_THAT(status, IsOk());
      EXPECT_EQ(std::min(read_size, input_size), buf_stream->Position());
      EXPECT_EQ(contents.substr(0, read_size), prefix);

      // Rewind, and disable rewinding.
      status = buf_stream->Rewind();
      EXPECT_THAT(status, IsOk());
      EXPECT_EQ(0, buf_stream->Position());
      buf_stream->DisableRewinding();
      status = buf_stream->Rewind();
      EXPECT_THAT(status, StatusIs(util::error::INVALID_ARGUMENT,
                                   HasSubstr("rewinding is disabled")));
      // Read the prefix again.
      status = ReadFromStream(buf_stream.get(), read_size, &prefix);
      EXPECT_THAT(status, IsOk());
      EXPECT_EQ(std::min(read_size, input_size), buf_stream->Position());
      EXPECT_EQ(contents.substr(0, read_size), prefix);

      // Read the rest of the input.
      std::string rest;
      status = ReadFromStream(buf_stream.get(), &rest);
      EXPECT_THAT(status, IsOk());
      EXPECT_EQ(input_size, buf_stream->Position());
      EXPECT_EQ(contents, prefix + rest);
    }
  }
}

}  // namespace
}  // namespace streamingaead
}  // namespace tink
}  // namespace crypto
