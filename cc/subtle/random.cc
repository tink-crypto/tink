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

#include "tink/subtle/random.h"

#include <cstring>
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

uint32_t Random::GetRandomUInt32() {
  uint8_t buf[sizeof(uint32_t)];
  RAND_bytes(buf, sizeof(uint32_t));
  uint32_t result;
  std::memcpy(&result, buf, sizeof(uint32_t));
  return result;
}

uint16_t Random::GetRandomUInt16() {
  uint8_t buf[sizeof(uint16_t)];
  RAND_bytes(buf, sizeof(uint16_t));
  uint16_t result;
  std::memcpy(&result, buf, sizeof(uint16_t));
  return result;
}

uint8_t Random::GetRandomUInt8() {
  uint8_t result;
  RAND_bytes(&result, 1);
  return result;
}

util::SecretData Random::GetRandomKeyBytes(size_t length) {
  util::SecretData buf(length, 0);
  // BoringSSL documentation says that it always returns 1; while
  // OpenSSL documentation says that it returns 1 on success, 0 otherwise. We
  // use BoringSSL, so we don't check the return value.
  RAND_bytes(buf.data(), buf.size());
  return buf;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
