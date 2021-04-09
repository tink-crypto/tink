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

#ifndef TINK_SUBTLE_SUBTLE_UTIL_H_
#define TINK_SUBTLE_SUBTLE_UTIL_H_

#include <cstdint>
#include <string>

namespace crypto {
namespace tink {
namespace subtle {

// Returnes big endian order representation of |val|.
std::string BigEndian32(uint32_t val);

// Like string::resize, but the newly allocated storage may be left
// uninitialized. C++11 provides no portable way to do this. Using this function
// allows us to do this on a per compiler/library version basis.
void ResizeStringUninitialized(std::string* s, size_t new_size);

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_SUBTLE_UTIL_H_
