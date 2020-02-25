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

#include "tink/util/secret_data_internal.h"

// placeholder for sanitization_functions include, please ignore

namespace crypto {
namespace tink {
namespace util {
namespace internal {

void TrackSensitiveMemory(void*, std::size_t) {}

void UntrackAndSanitizeSensitiveMemory(void* ptr, std::size_t n) {
  volatile char* s = static_cast<char*>(ptr);
  while (n--) {
    *s++ = 0;
  }
}

}  // namespace internal
}  // namespace util
}  // namespace tink
}  // namespace crypto
