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
#include "tink/aead/internal/aead_from_zero_copy.h"

#include <string>

#include "absl/memory/memory.h"
#include "tink/aead/internal/zero_copy_aead.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

util::StatusOr<std::string> AeadFromZeroCopy::Encrypt(
    absl::string_view plaintext, absl::string_view associated_data) const {
  std::string result;
  subtle::ResizeStringUninitialized(&result,
                                    aead_->MaxEncryptionSize(plaintext.size()));
  util::StatusOr<uint64_t> written_bytes = aead_->Encrypt(
      plaintext, associated_data, absl::MakeSpan(&result[0], result.size()));
  if (!written_bytes.ok()) {
    return written_bytes.status();
  }
  result.resize(*written_bytes);
  return result;
}

util::StatusOr<std::string> AeadFromZeroCopy::Decrypt(
    absl::string_view ciphertext, absl::string_view associated_data) const {
  std::string result;
  subtle::ResizeStringUninitialized(
      &result, aead_->MaxDecryptionSize(ciphertext.size()));
  util::StatusOr<uint64_t> bytes_written = aead_->Decrypt(
      ciphertext, associated_data, absl::MakeSpan(&result[0], result.size()));
  if (!bytes_written.ok()) {
    return bytes_written.status();
  }
  result.resize(*bytes_written);
  return result;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
