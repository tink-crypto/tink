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

#include "tink/subtle/subtle_util.h"

#include <cstdint>

#include "gtest/gtest.h"

TEST(SubtleUtilTest, Basic) {
  std::vector<uint8_t> dst(4);
  crypto::tink::subtle::BigEndianStore32(0x12345678, dst.data());
  EXPECT_EQ(dst[0], 0x12);
  EXPECT_EQ(dst[1], 0x34);
  EXPECT_EQ(dst[2], 0x56);
  EXPECT_EQ(dst[3], 0x78);
}
