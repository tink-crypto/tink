// Copyright 2017 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/subtle/random.h"

#include <set>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::testing::Gt;
using ::testing::Lt;
using ::testing::SizeIs;

TEST(RandomTest, testBasic) {
  int numTests = 32;
  absl::flat_hash_set<std::string> rand_strings;
  for (int i = 0; i < numTests; i++) {
    std::string s = Random::GetRandomBytes(16);
    EXPECT_THAT(s, SizeIs(16));
    rand_strings.insert(s);
  }
  EXPECT_THAT(rand_strings, SizeIs(numTests));
}

TEST(RandomTest, KeyBytesTest) {
  util::SecretData key = Random::GetRandomKeyBytes(16);
  EXPECT_THAT(key, SizeIs(16));
}

TEST(RandomTest, KeyBytesUniqueTest) {
  int numTests = 32;
  absl::flat_hash_set<util::SecretData> rand_strings;
  for (int i = 0; i < numTests; i++) {
    rand_strings.insert(Random::GetRandomKeyBytes(16));
  }
  EXPECT_THAT(rand_strings, SizeIs(numTests));
}

TEST(RandomTest, KeyBytesStatisticsTest) {
  constexpr int kByteLength = 32;
  std::vector<int> bit_counts(8 * kByteLength);
  const int kTests = 10000;
  for (int i = 0; i < kTests; ++i) {
    util::SecretData random = Random::GetRandomKeyBytes(kByteLength);
    for (int bit = 0; bit < 8 * kByteLength; ++bit) {
      if (random[bit / 8] & (1 << (bit % 8))) {
        ++bit_counts[bit];
      }
    }
  }
  for (int i = 0; i < 8 * kByteLength; ++i) {
    EXPECT_THAT(bit_counts[i], Gt(kTests * 0.4)) << i;
    EXPECT_THAT(bit_counts[i], Lt(kTests * 0.6)) << i;
  }
}

TEST(RandomTest, UInt8Test) {
  const int bit_length = 8;
  std::vector<int> bit_counts(bit_length);
  const int kTests = 10000;
  for (int i = 0; i < kTests; ++i) {
    uint8_t random = Random::GetRandomUInt8();
    for (int bit = 0; bit < bit_length; ++bit) {
      if (random & (1 << bit)) {
        ++bit_counts[bit];
      }
    }
  }
  for (int i = 0; i < bit_length; ++i) {
    EXPECT_THAT(bit_counts[i], Gt(kTests * 0.4)) << i;
    EXPECT_THAT(bit_counts[i], Lt(kTests * 0.6)) << i;
  }
}

TEST(RandomTest, UInt16Test) {
  const int bit_length = 16;
  std::vector<int> bit_counts(bit_length);
  const int kTests = 10000;
  for (int i = 0; i < kTests; ++i) {
    uint16_t random = Random::GetRandomUInt16();
    for (int bit = 0; bit < bit_length; ++bit) {
      if (random & (1 << bit)) {
        ++bit_counts[bit];
      }
    }
  }
  for (int i = 0; i < bit_length; ++i) {
    EXPECT_THAT(bit_counts[i], Gt(kTests * 0.4)) << i;
    EXPECT_THAT(bit_counts[i], Lt(kTests * 0.6)) << i;
  }
}

TEST(RandomTest, UInt32Test) {
  const int bit_length = 32;
  std::vector<int> bit_counts(bit_length);
  const int kTests = 10000;
  for (int i = 0; i < kTests; ++i) {
    uint32_t random = Random::GetRandomUInt32();
    for (int bit = 0; bit < bit_length; ++bit) {
      if (random & (1 << bit)) {
        ++bit_counts[bit];
      }
    }
  }
  for (int i = 0; i < bit_length; ++i) {
    EXPECT_THAT(bit_counts[i], Gt(kTests * 0.4)) << i;
    EXPECT_THAT(bit_counts[i], Lt(kTests * 0.6)) << i;
  }
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
