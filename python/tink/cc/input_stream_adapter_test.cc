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

#include "tink/cc/input_stream_adapter.h"

#include <algorithm>
#include <sstream>
#include <string>
#include <utility>

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "tink/input_stream.h"
#include "tink/subtle/random.h"
#include "tink/util/istream_input_stream.h"

namespace crypto {
namespace tink {
namespace {

std::unique_ptr<InputStreamAdapter> GetInputStreamAdapter(
    int buffer_size, const std::string& data) {
  auto string_stream = absl::make_unique<std::stringstream>();
  string_stream->write(data.data(), data.size());
  auto input_stream = absl::make_unique<util::IstreamInputStream>(
      std::move(string_stream), buffer_size);
  return absl::make_unique<InputStreamAdapter>(std::move(input_stream));
}

TEST(InputStreamAdapterTest, BasicRead) {
  std::string data = subtle::Random::GetRandomBytes(10);
  auto adapter = GetInputStreamAdapter(-1, data);
  auto read_result = adapter->Read(10);
  ASSERT_TRUE(read_result.status().ok()) << read_result.status();
  EXPECT_EQ(read_result.value(), data);
}

TEST(InputStreamAdapterTest, ReadEOFError) {
  std::string data = subtle::Random::GetRandomBytes(10);
  auto adapter = GetInputStreamAdapter(-1, data);
  auto read_result = adapter->Read(10);
  ASSERT_TRUE(read_result.status().ok()) << read_result.status();
  EXPECT_EQ(read_result.value(), data);
  read_result = adapter->Read(10);
  EXPECT_EQ(read_result.status().code(), absl::StatusCode::kOutOfRange);
}

TEST(InputStreamAdapterTest, MultipleRead) {
  std::string data = subtle::Random::GetRandomBytes(15);
  auto adapter = GetInputStreamAdapter(-1, data);
  auto read_result = adapter->Read(5);
  ASSERT_TRUE(read_result.status().ok()) << read_result.status();
  EXPECT_EQ(read_result.value(), data.substr(0, 5));
  read_result = adapter->Read(5);
  ASSERT_TRUE(read_result.status().ok()) << read_result.status();
  EXPECT_EQ(read_result.value(), data.substr(5, 5));
  read_result = adapter->Read(5);
  ASSERT_TRUE(read_result.status().ok()) << read_result.status();
  EXPECT_EQ(read_result.value(), data.substr(10, 5));
}

// In this test size of the IstreamInputStream buffer is smaller than the
// size of data to be read. Only one call to Next() is made and hence the output
// is smaller.
TEST(InputStreamAdapterTest, OnlyOneNext) {
  std::string data = subtle::Random::GetRandomBytes(40);
  auto adapter = GetInputStreamAdapter(10, data);
  auto read_result = adapter->Read(35);
  ASSERT_TRUE(read_result.status().ok()) << read_result.status();
  EXPECT_EQ(read_result.value(), data.substr(0, 10));
}

TEST(InputStreamAdapterTest, ReadLessThanAvailable) {
  std::string data = subtle::Random::GetRandomBytes(20);
  auto adapter = GetInputStreamAdapter(-1, data);
  auto read_result = adapter->Read(10);
  ASSERT_TRUE(read_result.status().ok()) << read_result.status();
  EXPECT_EQ(read_result.value(), data.substr(0, 10));
}

TEST(InputStreamAdapterTest, ReadMoreThanAvailable) {
  std::string data = subtle::Random::GetRandomBytes(20);
  auto adapter = GetInputStreamAdapter(-1, data);
  auto read_result = adapter->Read(30);
  ASSERT_TRUE(read_result.status().ok()) << read_result.status();
  EXPECT_EQ(read_result.value(), data);
}

TEST(InputStreamAdapterTest, ReadFromEmptyStream) {
  auto adapter = GetInputStreamAdapter(-1, "");
  auto read_result = adapter->Read(10);
  EXPECT_EQ(read_result.status().code(), absl::StatusCode::kOutOfRange);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
