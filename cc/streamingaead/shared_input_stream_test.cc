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

#include "tink/streamingaead/shared_input_stream.h"

#include <sstream>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/input_stream.h"
#include "tink/streamingaead/buffered_input_stream.h"
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
    return util::Status(absl::StatusCode::kInternal,
                        "Illegal read from a stream");
  }
  const void* buffer;
  output->clear();
  int bytes_to_read = count;
  while (bytes_to_read > 0) {
    auto next_result = input_stream->Next(&buffer);
    if (next_result.status().code() == absl::StatusCode::kOutOfRange) {
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

TEST(SharedInputStreamTest, BasicOperations) {
  for (auto input_size : {0, 1, 10, 100, 1000, 10000, 100000}) {
    std::string contents = subtle::Random::GetRandomBytes(input_size);
    auto input_stream = GetInputStream(contents);
    auto buffered_stream =
        std::make_shared<BufferedInputStream>(std::move(input_stream));
    for (auto read_size : {0, 1, 10, 123, 300}) {
      SCOPED_TRACE(absl::StrCat("input_size = ", input_size,
                                ", read_size = ", read_size));
      {
        auto shared_stream =
            absl::make_unique<SharedInputStream>(buffered_stream.get());

        // Read a prefix of the stream.
        std::string prefix;
        auto status = ReadFromStream(shared_stream.get(), read_size, &prefix);
        EXPECT_THAT(status, IsOk());
        EXPECT_EQ(std::min(read_size, input_size), shared_stream->Position());
        EXPECT_EQ(contents.substr(0, read_size), prefix);
        EXPECT_EQ(buffered_stream->Position(), shared_stream->Position());

        // Read the rest of the stream.
        std::string rest;
        status = ReadFromStream(shared_stream.get(), &rest);
        EXPECT_THAT(status, IsOk());
        EXPECT_EQ(input_size, shared_stream->Position());
        EXPECT_EQ(contents, prefix + rest);
        EXPECT_EQ(buffered_stream->Position(), shared_stream->Position());

        // Try reading again, should get an empty string.
        status = ReadFromStream(shared_stream.get(), &rest);
        EXPECT_THAT(status, IsOk());
        EXPECT_EQ("", rest);
        EXPECT_EQ(buffered_stream->Position(), shared_stream->Position());
      }

      // Now that shared_stream is out of scope, we rewind the underlying
      // buffered_stream, so that the next read iteration starts from
      // the beginning.
      auto status = buffered_stream->Rewind();
      EXPECT_THAT(status, IsOk());
      EXPECT_EQ(0, buffered_stream->Position());
    }
  }
}


TEST(SharedInputStreamTest, SingleBackup) {
  for (auto input_size : {0, 1, 10, 100, 1000, 10000, 100000}) {
    std::string contents = subtle::Random::GetRandomBytes(input_size);
    auto input_stream = GetInputStream(contents);
    auto buffered_stream =
        std::make_shared<BufferedInputStream>(std::move(input_stream));
    for (auto read_size : {0, 1, 10, 123, 300, 1024}) {
      SCOPED_TRACE(absl::StrCat("input_size = ", input_size,
                                ", read_size = ", read_size));
      {
        auto shared_stream = absl::make_unique<SharedInputStream>(
            buffered_stream.get());

        // Read a part of the stream.
        std::string prefix;
        auto status = ReadFromStream(shared_stream.get(), read_size, &prefix);
        EXPECT_THAT(status, IsOk());
        EXPECT_EQ(std::min(read_size, input_size), shared_stream->Position());
        EXPECT_EQ(contents.substr(0, read_size), prefix);

        // Read the next block of the stream, and then back it up.
        const void* buf;
        int pos = shared_stream->Position();
        auto next_result = shared_stream->Next(&buf);
        if (read_size < input_size) {
          EXPECT_THAT(next_result.status(), IsOk());
          auto next_size = next_result.ValueOrDie();
          EXPECT_EQ(pos + next_size, shared_stream->Position());
          shared_stream->BackUp(next_size);
          EXPECT_EQ(pos, shared_stream->Position());
          shared_stream->BackUp(input_size);
          EXPECT_EQ(pos, shared_stream->Position());
        } else {
          EXPECT_THAT(next_result.status(),
                      StatusIs(absl::StatusCode::kOutOfRange));
        }

        // Read the rest of the input.
        std::string rest;
        status = ReadFromStream(shared_stream.get(), &rest);
        EXPECT_THAT(status, IsOk());
        EXPECT_EQ(input_size, shared_stream->Position());
        EXPECT_EQ(contents, prefix + rest);
      }
      // Now that shared_stream is out of scope, we rewind the underlying
      // buffered_stream, so that the next read iteration starts from
      // the beginning.
      auto status = buffered_stream->Rewind();
      EXPECT_THAT(status, IsOk());
      EXPECT_EQ(0, buffered_stream->Position());
    }
  }
}

TEST(SharedInputStreamTest, MultipleBackups) {
  int input_size = 70000;
  std::string contents = subtle::Random::GetRandomBytes(input_size);
  auto input_stream = GetInputStream(contents);
  auto buffered_stream =
      std::make_shared<BufferedInputStream>(std::move(input_stream));

  for (int i = 0; i < 2; i++) {  // Two rounds, to test with Rewind.
    auto status = buffered_stream->Rewind();
    EXPECT_THAT(status, IsOk());
    EXPECT_EQ(0, buffered_stream->Position());

    auto shared_stream = absl::make_unique<SharedInputStream>(
        buffered_stream.get());
    EXPECT_EQ(0, shared_stream->Position());

    const void* buffer;
    auto next_result = shared_stream->Next(&buffer);
    EXPECT_THAT(next_result.status(), IsOk());
    auto next_size = next_result.ValueOrDie();
    EXPECT_EQ(contents.substr(0, next_size),
              std::string(static_cast<const char*>(buffer), next_size));

    // BackUp several times, but in total fewer bytes than returned by Next().
    int total_backup_size = 0;
    for (auto backup_size : {0, 1, 5, 0, 10, 100, -42, 400, 20, -100}) {
      shared_stream->BackUp(backup_size);
      total_backup_size += std::max(0, backup_size);
      EXPECT_EQ(next_size - total_backup_size, shared_stream->Position());
      EXPECT_EQ(buffered_stream->Position(), shared_stream->Position());
    }
    EXPECT_GT(next_size, total_backup_size);

    // Call Next(), it should return exactly the backed up bytes.
    next_result = shared_stream->Next(&buffer);
    EXPECT_THAT(next_result.status(), IsOk());
    EXPECT_EQ(total_backup_size, next_result.ValueOrDie());
    EXPECT_EQ(next_size, shared_stream->Position());
    EXPECT_EQ(buffered_stream->Position(), shared_stream->Position());
    EXPECT_EQ(contents.substr(next_size - total_backup_size, total_backup_size),
              std::string(static_cast<const char*>(buffer), total_backup_size));
  }
}


}  // namespace
}  // namespace streamingaead
}  // namespace tink
}  // namespace crypto
