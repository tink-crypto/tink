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

#include "tink/subtle/subtle_util.h"

namespace crypto {
namespace tink {
namespace subtle {

void BigEndianStore32(uint32_t val, uint8_t* dst) {
  dst[0] = (val >> 24) & 0xff;
  dst[1] = (val >> 16) & 0xff;
  dst[2] = (val >> 8) & 0xff;
  dst[3] = val & 0xff;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
