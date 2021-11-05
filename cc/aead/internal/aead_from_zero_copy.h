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
#ifndef TINK_AEAD_INTERNAL_AEAD_FROM_ZERO_COPY_H_
#define TINK_AEAD_INTERNAL_AEAD_FROM_ZERO_COPY_H_

#include <memory>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/aead.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// Aead cipher form a zero-copy one. Given a zero-copy AEAD implementation e.g.,
// FooAeadZeroCopy, one can simply have:
//
// std::unique_ptr<Aead> aead =
//   std::make_unique<AeadFromZeroCopy>(std::move(zero_copy_aead));
class AeadFromZeroCopy : public Aead {
 public:
  explicit AeadFromZeroCopy(std::unique_ptr<ZeroCopyAead> aead)
      : aead_(std::move(aead)) {}

  crypto::tink::util::StatusOr<std::string> Encrypt(
      absl::string_view plaintext,
      absl::string_view associated_data) const override;

  crypto::tink::util::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext,
      absl::string_view associated_data) const override;

 private:
  const std::unique_ptr<ZeroCopyAead> aead_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_INTERNAL_AEAD_FROM_ZERO_COPY_H_
