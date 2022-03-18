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

#include "tink/cc/output_stream_adapter.h"

#include <algorithm>
#include <sstream>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/output_stream.h"
#include "tink/subtle/random.h"
#include "tink/util/ostream_output_stream.h"

namespace crypto {
namespace tink {
namespace {

std::unique_ptr<OutputStreamAdapter> GetOutputStreamAdapter(
    int buffer_size, std::stringbuf** buffer_ref) {
  auto string_stream = absl::make_unique<std::stringstream>();
  // Reference to the stringstream buffer used for later validation.
  *buffer_ref = string_stream->rdbuf();
  auto output_stream = absl::make_unique<util::OstreamOutputStream>(
      std::move(string_stream), buffer_size);
  return absl::make_unique<OutputStreamAdapter>(std::move(output_stream));
}

TEST(OutputStreamAdapterTest, Basic) {
  std::stringbuf* buffer_ref;
  auto adapter = GetOutputStreamAdapter(-1, &buffer_ref);
  auto write_result = adapter->Write("something");
  ASSERT_TRUE(write_result.status().ok());
  EXPECT_EQ(write_result.value(), 9);
  EXPECT_TRUE(adapter->Close().ok());
  EXPECT_EQ(buffer_ref->str(), "something");
}

TEST(OutputStreamAdapterTest, MultipleWrite) {
  std::stringbuf* buffer_ref;
  auto adapter = GetOutputStreamAdapter(-1, &buffer_ref);
  auto write_result = adapter->Write("something");
  ASSERT_TRUE(write_result.status().ok());
  EXPECT_EQ(write_result.value(), 9);
  write_result = adapter->Write("123");
  ASSERT_TRUE(write_result.status().ok());
  EXPECT_EQ(write_result.value(), 3);
  write_result = adapter->Write("456");
  ASSERT_TRUE(write_result.status().ok());
  EXPECT_EQ(write_result.value(), 3);
  EXPECT_TRUE(adapter->Close().ok());
  EXPECT_EQ(buffer_ref->str(), "something123456");
}

TEST(OutputStreamAdapterTest, WriteAfterClose) {
  std::stringbuf* buffer_ref;
  auto adapter = GetOutputStreamAdapter(-1, &buffer_ref);
  ASSERT_TRUE(adapter->Close().ok());
  auto status = adapter->Write("something").status();
  EXPECT_EQ(status.code(), absl::StatusCode::kFailedPrecondition);
  EXPECT_THAT(std::string(status.message()),
              testing::HasSubstr("Stream closed"));
}

// In this test size of the OstreamOutputStream buffer is smaller than the
// size of data to be written, so multiple calls to Next() will be needed.
TEST(OutputStreamAdapterTest, MultipleNext) {
  std::stringbuf* buffer_ref;
  auto adapter = GetOutputStreamAdapter(10, &buffer_ref);
  std::string data = subtle::Random::GetRandomBytes(35);
  auto write_result = adapter->Write(data);
  ASSERT_TRUE(write_result.status().ok());
  EXPECT_EQ(write_result.value(), 35);
  EXPECT_TRUE(adapter->Close().ok());
  EXPECT_EQ(buffer_ref->str(), data);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
