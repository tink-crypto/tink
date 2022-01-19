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

#include "tink/subtle/aes_gcm_boringssl.h"

#include <memory>
#include <utility>

#include "absl/memory/memory.h"
#include "tink/aead/internal/aead_from_zero_copy.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/aead/internal/zero_copy_aes_gcm_boringssl.h"
#include "tink/internal/fips_utils.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

util::StatusOr<std::unique_ptr<Aead>> AesGcmBoringSsl::New(
    const util::SecretData& key) {
  util::Status status = internal::CheckFipsCompatibility<AesGcmBoringSsl>();
  if (!status.ok()) {
    return status;
  }

  util::StatusOr<std::unique_ptr<internal::ZeroCopyAead>> zero_copy_aead =
      internal::ZeroCopyAesGcmBoringSsl::New(key);
  if (!zero_copy_aead.ok()) {
    return zero_copy_aead.status();
  }
  return {absl::make_unique<internal::AeadFromZeroCopy>(
      *std::move(zero_copy_aead))};
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
