// Copyright 2020 Google LLC
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

#ifndef TINK_AEAD_MOCK_AEAD_H_
#define TINK_AEAD_MOCK_AEAD_H_

#include "gmock/gmock.h"
#include "tink/aead.h"

namespace crypto {
namespace tink {

class MockAead : public Aead {
 public:
  MOCK_METHOD(util::StatusOr<std::string>, Encrypt,
              (absl::string_view plaintext, absl::string_view associated_data),
              (const, override));

  MOCK_METHOD(util::StatusOr<std::string>, Decrypt,
              (absl::string_view ciphertext, absl::string_view associated_data),
              (const, override));
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_MOCK_AEAD_H_
