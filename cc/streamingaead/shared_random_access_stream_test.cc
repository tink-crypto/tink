// Copyright 2019 Google LLC
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

#include "tink/streamingaead/shared_random_access_stream.h"

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "tink/random_access_stream.h"
#include "tink/util/file_random_access_stream.h"
#include "tink/util/buffer.h"
#include "tink/util/status.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace streamingaead {
namespace {

// Reads the entire 'ra_stream' in chunks of size 'chunk_size',
// until no more bytes can be read, and puts the read bytes into 'contents'.
// Returns the status of the last ra_stream->Next()-operation.
util::Status ReadAll(RandomAccessStream* ra_stream, int chunk_size,
                     std::string* contents) {
  contents->clear();
  auto buffer = std::move(util::Buffer::New(chunk_size).ValueOrDie());
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

TEST(SharedRandomAccessStreamTest, ReadingStreams) {
  for (auto stream_size : {0, 10, 100, 1000, 10000, 1000000}) {
    SCOPED_TRACE(absl::StrCat("stream_size = ", stream_size));
    std::string file_contents;
    std::string filename = absl::StrCat(stream_size, "_reading_test.bin");
    int input_fd = test::GetTestFileDescriptor(
        filename, stream_size, &file_contents);
    EXPECT_EQ(stream_size, file_contents.size());
    auto ra_stream = absl::make_unique<util::FileRandomAccessStream>(input_fd);
    SharedRandomAccessStream shared_stream(ra_stream.get());
    std::string stream_contents;
    auto status = ReadAll(&shared_stream, 1 + (stream_size / 10),
                          &stream_contents);
    EXPECT_EQ(absl::StatusCode::kOutOfRange, status.code());
    EXPECT_EQ("EOF", status.message());
    EXPECT_EQ(file_contents, stream_contents);
    EXPECT_EQ(stream_size, shared_stream.size().ValueOrDie());
  }
}


}  // namespace
}  // namespace streamingaead
}  // namespace tink
}  // namespace crypto
