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

#ifndef TINK_SUBTLE_RANDOM_H_
#define TINK_SUBTLE_RANDOM_H_

#include <memory>
#include <string>

#include "tink/util/secret_data.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace subtle {

class Random {
 public:
  // Fills the given `buffer` with random bytes.
  static util::Status GetRandomBytes(absl::Span<char> buffer);
  // Returns a random string of desired length.
  static std::string GetRandomBytes(size_t length);
  static uint32_t GetRandomUInt32();
  static uint16_t GetRandomUInt16();
  static uint8_t GetRandomUInt8();
  // Returns length bytes of random data stored in specialized key container.
  static util::SecretData GetRandomKeyBytes(size_t length);
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_RANDOM_H_
