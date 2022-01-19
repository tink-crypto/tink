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
#include "absl/types/span.h"
#include "tink/util/secret_data.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

// Iterations for statistic tests.
constexpr int kTests = 10000;

using ::testing::Gt;
using ::testing::Lt;
using ::testing::SizeIs;
using ::crypto::tink::test::IsOk;

TEST(RandomTest, MultipleFilledBuffersAreUnique) {
  constexpr int kNumRandomItems = 32;
  absl::flat_hash_set<std::string> random_strings;
  for (int i = 0; i < kNumRandomItems; i++) {
    std::string s(16, '\0');
    EXPECT_THAT(Random::GetRandomBytes(absl::MakeSpan(s)), IsOk());
    random_strings.insert(s);
  }
  EXPECT_THAT(random_strings, SizeIs(kNumRandomItems));
}

TEST(RandomTest, MultipleGeneratedRandomStringAreUnique) {
  constexpr int kNumRandomItems = 32;
  absl::flat_hash_set<std::string> random_strings;
  for (int i = 0; i < kNumRandomItems; i++) {
    std::string s = Random::GetRandomBytes(16);
    EXPECT_THAT(s, SizeIs(16));
    random_strings.insert(s);
  }
  EXPECT_THAT(random_strings, SizeIs(kNumRandomItems));
}


TEST(RandomTest, MultipleGeneratedSecretDataAreUnique) {
  constexpr int kNumRandomItems = 32;
  absl::flat_hash_set<util::SecretData> random_keys;
  for (int i = 0; i < kNumRandomItems; i++) {
    util::SecretData key = Random::GetRandomKeyBytes(16);
    EXPECT_THAT(key, SizeIs(16));
    random_keys.insert(key);
  }
  EXPECT_THAT(random_keys, SizeIs(kNumRandomItems));
}

TEST(RandomTest, KeyBytesRandomGenerationIsUniform) {
  constexpr int kKeyLengthInBytes = 32;
  std::vector<int> bit_counts(8 * kKeyLengthInBytes);
  for (int i = 0; i < kTests; ++i) {
    util::SecretData random = Random::GetRandomKeyBytes(kKeyLengthInBytes);
    for (int bit = 0; bit < 8 * kKeyLengthInBytes; ++bit) {
      if (random[bit / 8] & (1 << (bit % 8))) {
        ++bit_counts[bit];
      }
    }
  }
  for (int i = 0; i < 8 * kKeyLengthInBytes; ++i) {
    EXPECT_THAT(bit_counts[i], Gt(kTests * 0.4)) << i;
    EXPECT_THAT(bit_counts[i], Lt(kTests * 0.6)) << i;
  }
}

TEST(RandomTest, UInt8RandomGenerationIsUniform) {
  const int kNumBits = 8;
  std::vector<int> bit_counts(kNumBits);
  for (int i = 0; i < kTests; ++i) {
    uint8_t random = Random::GetRandomUInt8();
    for (int bit = 0; bit < kNumBits; ++bit) {
      if (random & (1 << bit)) {
        ++bit_counts[bit];
      }
    }
  }
  for (int i = 0; i < kNumBits; ++i) {
    EXPECT_THAT(bit_counts[i], Gt(kTests * 0.4)) << i;
    EXPECT_THAT(bit_counts[i], Lt(kTests * 0.6)) << i;
  }
}

TEST(RandomTest, UInt16RandomGenerationIsUniform) {
  const int kNumBits = 16;
  std::vector<int> bit_counts(kNumBits);
  for (int i = 0; i < kTests; ++i) {
    uint16_t random = Random::GetRandomUInt16();
    for (int bit = 0; bit < kNumBits; ++bit) {
      if (random & (1 << bit)) {
        ++bit_counts[bit];
      }
    }
  }
  for (int i = 0; i < kNumBits; ++i) {
    EXPECT_THAT(bit_counts[i], Gt(kTests * 0.4)) << i;
    EXPECT_THAT(bit_counts[i], Lt(kTests * 0.6)) << i;
  }
}

TEST(RandomTest, UInt32RandomGenerationIsUniform) {
  const int kNumBits = 32;
  std::vector<int> bit_counts(kNumBits);
  for (int i = 0; i < kTests; ++i) {
    uint32_t random = Random::GetRandomUInt32();
    for (int bit = 0; bit < kNumBits; ++bit) {
      if (random & (1 << bit)) {
        ++bit_counts[bit];
      }
    }
  }
  for (int i = 0; i < kNumBits; ++i) {
    EXPECT_THAT(bit_counts[i], Gt(kTests * 0.4)) << i;
    EXPECT_THAT(bit_counts[i], Lt(kTests * 0.6)) << i;
  }
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
