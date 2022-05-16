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

#include "tink/util/buffer.h"

#include <cstring>
#include <utility>

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/subtle/random.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace util {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using testing::HasSubstr;

TEST(BufferTest, ExternalMemoryBlock) {
  for (auto buf_size : {1, 10, 100, 1000, 10000, 100000, 1000000}) {
    SCOPED_TRACE(absl::StrCat("buf_size = ", buf_size));
    auto mem_block = absl::make_unique<char[]>(buf_size);
    auto buf_result = Buffer::NewNonOwning(mem_block.get(), buf_size);
    ASSERT_THAT(buf_result.status(), IsOk());
    auto buf = std::move(buf_result.value());
    EXPECT_EQ(buf_size, buf->size());
    EXPECT_EQ(buf_size, buf->allocated_size());
    EXPECT_EQ(mem_block.get(), buf->get_mem_block());
    for (auto new_size : {0, 1, buf_size/2, buf_size}) {
      SCOPED_TRACE(absl::StrCat("new_size = ", buf_size));
      ASSERT_THAT(buf->set_size(new_size), IsOk());
      EXPECT_EQ(new_size, buf->size());
      EXPECT_EQ(buf_size, buf->allocated_size());
      EXPECT_EQ(mem_block.get(), buf->get_mem_block());
      auto data = subtle::Random::GetRandomBytes(new_size);
      std::memcpy(buf->get_mem_block(), data.data(), new_size);
      EXPECT_EQ(0, std::memcmp(data.data(), buf->get_mem_block(), new_size));
    }
  }
}

TEST(BufferTest, InternalMemoryBlock) {
  for (auto buf_size : {1, 10, 100, 1000, 10000, 100000, 1000000}) {
    SCOPED_TRACE(absl::StrCat("buf_size = ", buf_size));
    auto buf_result = Buffer::New(buf_size);
    ASSERT_THAT(buf_result.status(), IsOk());
    auto buf = std::move(buf_result.value());
    EXPECT_EQ(buf_size, buf->size());
    EXPECT_EQ(buf_size, buf->allocated_size());
    for (auto new_size : {0, 1, buf_size/2, buf_size}) {
      SCOPED_TRACE(absl::StrCat("new_size = ", buf_size));
      ASSERT_THAT(buf->set_size(new_size), IsOk());
      EXPECT_EQ(new_size, buf->size());
      EXPECT_EQ(buf_size, buf->allocated_size());
      auto data = subtle::Random::GetRandomBytes(new_size);
      std::memcpy(buf->get_mem_block(), data.data(), new_size);
      EXPECT_EQ(0, std::memcmp(data.data(), buf->get_mem_block(), new_size));
    }
  }
}

TEST(BufferTest, NullMemoryBlock) {
  auto buf_result = Buffer::NewNonOwning(nullptr, 42);
  EXPECT_THAT(buf_result.status(), StatusIs(absl::StatusCode::kInvalidArgument,
                                            HasSubstr("non-null")));
}

TEST(BufferTest, BadAllocatedSize_ExternalMemoryBlock) {
  for (auto allocated_size : {-10, -1, 0}) {
    SCOPED_TRACE(absl::StrCat("allocated_size = ", allocated_size));
    auto mem_block = absl::make_unique<char[]>(42);
    auto buf_result = Buffer::NewNonOwning(mem_block.get(), allocated_size);
    EXPECT_THAT(buf_result.status(),
                StatusIs(absl::StatusCode::kInvalidArgument,
                         HasSubstr("allocated_size")));
  }
}

TEST(BufferTest, BadAllocatedSize_InternalMemoryBlock) {
  for (auto allocated_size : {-10, -1, 0}) {
    SCOPED_TRACE(absl::StrCat("allocated_size = ", allocated_size));
    auto buf_result = Buffer::New(allocated_size);
    EXPECT_THAT(buf_result.status(),
                StatusIs(absl::StatusCode::kInvalidArgument,
                         HasSubstr("allocated_size")));
  }
}

TEST(BufferTest, BadNewSize_ExternalMemoryBlock) {
  for (auto buf_size : {1, 10, 100, 1000, 10000}) {
    SCOPED_TRACE(absl::StrCat("buf_size = ", buf_size));
    auto buf = std::move(Buffer::New(buf_size).value());
    for (auto new_size : {-10, -1, buf_size + 1, 2 * buf_size}) {
      SCOPED_TRACE(absl::StrCat("new_size = ", buf_size));
      EXPECT_THAT(buf->set_size(new_size),
                  StatusIs(absl::StatusCode::kInvalidArgument,
                           HasSubstr("new_size must satisfy")));
    }
  }
}

TEST(BufferTest, BadNewSize_InternalMemoryBlock) {
  for (auto buf_size : {1, 10, 100, 1000, 10000}) {
    SCOPED_TRACE(absl::StrCat("buf_size = ", buf_size));
    auto mem_block = absl::make_unique<char[]>(buf_size);
    auto buf =
        std::move(Buffer::NewNonOwning(mem_block.get(), buf_size).value());
    for (auto new_size : {-10, -1, buf_size + 1, 2 * buf_size}) {
      SCOPED_TRACE(absl::StrCat("new_size = ", buf_size));
      EXPECT_THAT(buf->set_size(new_size),
                  StatusIs(absl::StatusCode::kInvalidArgument,
                           HasSubstr("new_size must satisfy")));
    }
  }
}

}  // namespace
}  // namespace util
}  // namespace tink
}  // namespace crypto
