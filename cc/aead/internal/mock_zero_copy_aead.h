// Copyright 2021 Google LLC
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
#ifndef TINK_AEAD_INTERNAL_MOCK_ZERO_COPY_AEAD_H_
#define TINK_AEAD_INTERNAL_MOCK_ZERO_COPY_AEAD_H_

#include "gmock/gmock.h"
#include "absl/strings/string_view.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

class MockZeroCopyAead : public ZeroCopyAead {
 public:
  ~MockZeroCopyAead() override = default;

  MOCK_METHOD(int64_t, MaxEncryptionSize, (int64_t plaintext_size),
              (const, override));

  MOCK_METHOD(crypto::tink::util::StatusOr<int64_t>, Encrypt,
              (absl::string_view plaintext, absl::string_view associated_data,
               absl::Span<char> buffer),
              (const, override));

  MOCK_METHOD(int64_t, MaxDecryptionSize, (int64_t ciphertext_size),
              (const, override));

  MOCK_METHOD(crypto::tink::util::StatusOr<int64_t>, Decrypt,
              (absl::string_view ciphertext, absl::string_view associated_data,
               absl::Span<char> buffer),
              (const, override));
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_MOCK_ZERO_COPY_AEAD_H_
