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

#include "tink/subtle/subtle_util.h"

#include <string>
// placeholder_subtle_util_cc

namespace crypto {
namespace tink {
namespace subtle {

std::string BigEndian32(uint32_t val) {
  std::string result(4, '\0');
  result[0] = (val >> 24) & 0xff;
  result[1] = (val >> 16) & 0xff;
  result[2] = (val >> 8) & 0xff;
  result[3] = val & 0xff;
  return result;
}

void ResizeStringUninitialized(std::string* s, size_t new_size) {
  s->resize(new_size);
}


}  // namespace subtle
}  // namespace tink
}  // namespace crypto
