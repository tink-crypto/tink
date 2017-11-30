// Copyright 2017 Google Inc.
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

#include "cc/subtle/random.h"
#include <string>
#include "openssl/rand.h"

namespace crypto {
namespace tink {
namespace subtle {

// static
std::string Random::GetRandomBytes(size_t length) {
  std::unique_ptr<uint8_t[]> buf(new uint8_t[length]);
  // BoringSSL documentation says that it always returns 1; while
  // OpenSSL documentation says that it returns 1 on success, 0 otherwise. We
  // use BoringSSL, so we don't check the return value.
  RAND_bytes(buf.get(), length);
  return std::string(reinterpret_cast<const char *>(buf.get()), length);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
