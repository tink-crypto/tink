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

#include <cstdint>
#include <string>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/types/span.h"
#include "openssl/rand.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace subtle {

namespace {

template <typename UintType>
UintType GetRandomUint() {
  UintType result;
  Random::GetRandomBytes(
      absl::MakeSpan(reinterpret_cast<char *>(&result), sizeof(result)))
      .IgnoreError();
  return result;
}

}  // namespace

// BoringSSL documentation says that it always returns 1; while
// OpenSSL documentation says that it returns "1 on success, -1 if not supported
// by the current RAND method, or 0 on other failure"
// (https://www.openssl.org/docs/man1.1.1/man3/RAND_bytes.html).
//
// In case of insufficient entropy at the time of the call, BoringSSL's
// RAND_bytes will behave in different ways depending on the operating system,
// version, and FIPS mode. For Linux with a semi-recent kernel, it will block
// until the system has collected at least 128 bits since boot. For old
// kernels without getrandom support (and not in FIPS mode), it will resort to
// /dev/urandom.
util::Status Random::GetRandomBytes(absl::Span<char> buffer) {
  auto buffer_ptr = reinterpret_cast<uint8_t *>(buffer.data());
  if (RAND_bytes(buffer_ptr, buffer.size()) <= 0) {
    return util::Status(absl::StatusCode::kInternal,
                        absl::StrCat("RAND_bytes failed to generate ",
                                     buffer.size(), " bytes"));
  }
  return util::OkStatus();
}

std::string Random::GetRandomBytes(size_t length) {
  std::string buffer;
  ResizeStringUninitialized(&buffer, length);
  // TODO(b/207466225): Modify the return to be a StatusOr<std::string> as
  // OpenSSL can return an error.
  GetRandomBytes(absl::MakeSpan(buffer)).IgnoreError();
  return buffer;
}

uint32_t Random::GetRandomUInt32() { return GetRandomUint<uint32_t>(); }
uint16_t Random::GetRandomUInt16() { return GetRandomUint<uint16_t>(); }
uint8_t Random::GetRandomUInt8() { return GetRandomUint<uint8_t>(); }

util::SecretData Random::GetRandomKeyBytes(size_t length) {
  util::SecretData buf(length, 0);
  GetRandomBytes(
      absl::MakeSpan(reinterpret_cast<char *>(buf.data()), buf.size()))
      .IgnoreError();
  return buf;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
