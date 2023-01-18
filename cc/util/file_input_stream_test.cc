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
#include "tink/util/file_input_stream.h"

#include <algorithm>
#include <cstdint>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;

constexpr int kDefaultTestStreamSize = 100 * 1024;  // 100 KB.

// Reads the specified `input_stream` until no more bytes can be read,
// and puts the read bytes into `contents`.
// Returns the status of the last input_stream->Next()-operation.
util::Status ReadAll(util::FileInputStream* input_stream,
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

using FileInputStreamTestDefaultBufferSize = testing::TestWithParam<int>;

TEST_P(FileInputStreamTestDefaultBufferSize, ReadAllfFromInputStreamSucceeds) {
  int stream_size = GetParam();
  SCOPED_TRACE(absl::StrCat("stream_size = ", stream_size));
  std::string file_contents;
  std::string filename = absl::StrCat(stream_size, "_reading_test.bin");
  int input_fd =
      test::GetTestFileDescriptor(filename, stream_size, &file_contents);
  EXPECT_EQ(stream_size, file_contents.size());
  auto input_stream = absl::make_unique<util::FileInputStream>(input_fd);
  std::string stream_contents;
  auto status = ReadAll(input_stream.get(), &stream_contents);
  EXPECT_THAT(status, StatusIs(absl::StatusCode::kOutOfRange));
  EXPECT_EQ(status.message(), "EOF");
  EXPECT_EQ(file_contents, stream_contents);
}

INSTANTIATE_TEST_SUITE_P(FileInputStreamTest,
                         FileInputStreamTestDefaultBufferSize,
                         testing::ValuesIn({0, 10, 100, 1000, 10000, 100000,
                                            1000000}));

using FileInputStreamTestCustomBufferSizes = testing::TestWithParam<int>;

TEST_P(FileInputStreamTestCustomBufferSizes,
       ReadAllWithCustomBufferSizeSucceeds) {
  int buffer_size = GetParam();
  SCOPED_TRACE(absl::StrCat("buffer_size = ", buffer_size));
  std::string file_contents;
  std::string filename = absl::StrCat(buffer_size, "_buffer_size_test.bin");
  int input_fd = test::GetTestFileDescriptor(filename, kDefaultTestStreamSize,
                                             &file_contents);
  EXPECT_EQ(kDefaultTestStreamSize, file_contents.size());
  auto input_stream =
      absl::make_unique<util::FileInputStream>(input_fd, buffer_size);
  const void* buffer;
  auto next_result = input_stream->Next(&buffer);
  ASSERT_THAT(next_result, IsOk());
  EXPECT_EQ(buffer_size, next_result.value());
  EXPECT_EQ(file_contents.substr(0, buffer_size),
            std::string(static_cast<const char*>(buffer), buffer_size));
}

INSTANTIATE_TEST_SUITE_P(FileInputStreamTest,
                         FileInputStreamTestCustomBufferSizes,
                         testing::ValuesIn({1, 10, 100, 1000, 10000}));

TEST(FileInputStreamTest, NextFailsIfFdIsInvalid) {
  int buffer_size = 4 * 1024;
  auto input_stream = absl::make_unique<util::FileInputStream>(-1, buffer_size);
  const void* buffer = nullptr;
  EXPECT_THAT(input_stream->Next(&buffer).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(FileInputStreamTest, NextFailsIfDataIsNull) {
  int buffer_size = 4 * 1024;
  std::string file_contents;
  std::string filename = absl::StrCat(buffer_size, "_backup_test.bin");
  int input_fd = test::GetTestFileDescriptor(filename, kDefaultTestStreamSize,
                                             &file_contents);
  EXPECT_EQ(kDefaultTestStreamSize, file_contents.size());
  auto input_stream =
      absl::make_unique<util::FileInputStream>(input_fd, buffer_size);

  EXPECT_THAT(input_stream->Next(nullptr).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(FileInputStreamTest, NextReadsExactlyOneBlockOfData) {
  int buffer_size = 4 * 1024;
  std::string file_contents;
  std::string filename = absl::StrCat(buffer_size, "_backup_test.bin");
  int input_fd = test::GetTestFileDescriptor(filename, kDefaultTestStreamSize,
                                             &file_contents);
  EXPECT_EQ(kDefaultTestStreamSize, file_contents.size());
  auto input_stream =
      absl::make_unique<util::FileInputStream>(input_fd, buffer_size);

  auto expected_file_content_block =
      absl::string_view(file_contents).substr(0, buffer_size);
  const void* buffer = nullptr;
  util::StatusOr<int> next_result = input_stream->Next(&buffer);
  ASSERT_THAT(next_result, IsOkAndHolds(buffer_size));
  // Check that we advanced of buffer_size bytes.
  EXPECT_EQ(input_stream->Position(), buffer_size);
  EXPECT_EQ(absl::string_view(static_cast<const char*>(buffer), buffer_size),
            expected_file_content_block);
}

TEST(FileInputStreamTest, BackupForNegativeOrZeroBytesIsANoop) {
  int buffer_size = 4 * 1024;
  std::string file_contents;
  std::string filename = absl::StrCat(buffer_size, "_backup_test.bin");
  int input_fd = test::GetTestFileDescriptor(filename, kDefaultTestStreamSize,
                                             &file_contents);
  EXPECT_EQ(kDefaultTestStreamSize, file_contents.size());
  auto input_stream =
      absl::make_unique<util::FileInputStream>(input_fd, buffer_size);
  EXPECT_EQ(input_stream->Position(), 0);

  auto expected_file_content_block =
      absl::string_view(file_contents).substr(0, buffer_size);
  const void* buffer = nullptr;
  ASSERT_THAT(input_stream->Next(&buffer), IsOkAndHolds(buffer_size));
  // Check that we advanced of buffer_size bytes.
  EXPECT_EQ(input_stream->Position(), buffer_size);
  EXPECT_EQ(absl::string_view(static_cast<const char*>(buffer), buffer_size),
            expected_file_content_block);

  // The calls below are noops.
  input_stream->BackUp(0);
  EXPECT_EQ(input_stream->Position(), buffer_size);
  input_stream->BackUp(-12);
  EXPECT_EQ(input_stream->Position(), buffer_size);

  // A subsequent call to `Next` returns the 2nd block.
  auto expected_2nd_file_content_block =
      absl::string_view(file_contents).substr(buffer_size, buffer_size);
  ASSERT_THAT(input_stream->Next(&buffer), IsOkAndHolds(buffer_size));
  // Check that we advanced of buffer_size bytes.
  EXPECT_EQ(input_stream->Position(), 2 * buffer_size);
  EXPECT_EQ(absl::string_view(static_cast<const char*>(buffer), buffer_size),
            expected_2nd_file_content_block);
}

TEST(FileInputStreamTest, BackupForLessThanOneBlockOfData) {
  int buffer_size = 4 * 1024;
  std::string file_contents;
  std::string filename = absl::StrCat(buffer_size, "_backup_test.bin");
  int input_fd = test::GetTestFileDescriptor(filename, kDefaultTestStreamSize,
                                             &file_contents);
  EXPECT_EQ(kDefaultTestStreamSize, file_contents.size());
  auto input_stream =
      absl::make_unique<util::FileInputStream>(input_fd, buffer_size);

  auto expected_file_content_block =
      absl::string_view(file_contents).substr(0, buffer_size);
  const void* buffer = nullptr;
  ASSERT_THAT(input_stream->Next(&buffer), IsOkAndHolds(buffer_size));
  // Check that we advanced of buffer_size bytes.
  EXPECT_EQ(input_stream->Position(), buffer_size);
  EXPECT_EQ(absl::string_view(static_cast<const char*>(buffer), buffer_size),
            expected_file_content_block);

  int64_t position_after_next = input_stream->Position();
  // Number of bytes that were backed up.
  int num_backed_up_bytes = 0;
  input_stream->BackUp(0);  // This should be a noop.
  EXPECT_EQ(input_stream->Position(), position_after_next);
  input_stream->BackUp(-12);  // This should be a noop.
  EXPECT_EQ(input_stream->Position(), position_after_next);
  input_stream->BackUp(10);
  num_backed_up_bytes += 10;
  EXPECT_EQ(input_stream->Position(),
            position_after_next - num_backed_up_bytes);
  input_stream->BackUp(5);
  num_backed_up_bytes += 5;
  EXPECT_EQ(input_stream->Position(),
            position_after_next - num_backed_up_bytes);

  // A subsequent call to Next should return only the backed up bytes.
  auto expected_backed_up_bytes =
      absl::string_view(file_contents)
          .substr(buffer_size - num_backed_up_bytes, num_backed_up_bytes);
  ASSERT_THAT(input_stream->Next(&buffer),
              IsOkAndHolds(expected_backed_up_bytes.size()));
  EXPECT_EQ(absl::string_view(static_cast<const char*>(buffer),
                              expected_backed_up_bytes.size()),
            expected_backed_up_bytes);
}

// When backing up of a number of bytes larger than the size of a block, backup
// of one block.
TEST(FileInputStreamTest, BackupAtMostOfOneBlock) {
  int buffer_size = 4 * 1024;
  std::string file_contents;
  std::string filename = absl::StrCat(buffer_size, "_backup_test.bin");
  int input_fd = test::GetTestFileDescriptor(filename, kDefaultTestStreamSize,
                                             &file_contents);
  EXPECT_EQ(kDefaultTestStreamSize, file_contents.size());
  auto input_stream =
      absl::make_unique<util::FileInputStream>(input_fd, buffer_size);

  // Read two blocks of size buffer_size, then back up of more than buffer_size
  // bytes.
  auto expected_1st_file_content_block =
      absl::string_view(file_contents).substr(0, buffer_size);
  const void* buffer = nullptr;
  ASSERT_THAT(input_stream->Next(&buffer), IsOkAndHolds(buffer_size));
  // Check that we advanced of buffer_size bytes.
  EXPECT_EQ(input_stream->Position(), buffer_size);
  EXPECT_EQ(absl::string_view(static_cast<const char*>(buffer), buffer_size),
            expected_1st_file_content_block);

  auto expected_2nd_file_content_block =
      absl::string_view(file_contents).substr(buffer_size, buffer_size);
  ASSERT_THAT(input_stream->Next(&buffer), IsOkAndHolds(buffer_size));
  // Check that we advanced of buffer_size bytes.
  EXPECT_EQ(input_stream->Position(), 2 * buffer_size);
  EXPECT_EQ(absl::string_view(static_cast<const char*>(buffer), buffer_size),
            expected_2nd_file_content_block);

  int64_t position_after_next = input_stream->Position();
  EXPECT_EQ(input_stream->Position(), position_after_next);
  input_stream->BackUp(10);
  EXPECT_EQ(input_stream->Position(), position_after_next - 10);
  input_stream->BackUp(buffer_size);
  EXPECT_EQ(input_stream->Position(), position_after_next - buffer_size);

  // This call to Next is expected to read the second block again.
  ASSERT_THAT(input_stream->Next(&buffer), IsOkAndHolds(buffer_size));
  EXPECT_EQ(absl::string_view(static_cast<const char*>(buffer), buffer_size),
            expected_2nd_file_content_block);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
