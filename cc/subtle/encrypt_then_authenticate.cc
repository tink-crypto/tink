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

#include "tink/subtle/encrypt_then_authenticate.h"

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/internal/util.h"
#include "tink/mac.h"
#include "tink/subtle/ind_cpa_cipher.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

static const std::string longToBigEndianStr(uint64_t value) {
  uint8_t bytes[8];
  for (int i = sizeof(bytes) - 1; i >= 0; i--) {
    bytes[i] = value & 0xff;
    value >>= 8;
  }
  return std::string(reinterpret_cast<const char*>(&bytes[0]), sizeof(bytes));
}

util::StatusOr<std::unique_ptr<Aead>> EncryptThenAuthenticate::New(
    std::unique_ptr<IndCpaCipher> ind_cpa_cipher, std::unique_ptr<Mac> mac,
    uint8_t tag_size) {
  if (tag_size < kMinTagSizeInBytes) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "tag size too small");
  }
  std::unique_ptr<Aead> aead(new EncryptThenAuthenticate(
      std::move(ind_cpa_cipher), std::move(mac), tag_size));
  return std::move(aead);
}

util::StatusOr<std::string> EncryptThenAuthenticate::Encrypt(
    absl::string_view plaintext, absl::string_view associated_data) const {
  // BoringSSL expects a non-null pointer for plaintext and associated_data,
  // regardless of whether the size is 0.
  plaintext = internal::EnsureStringNonNull(plaintext);
  associated_data = internal::EnsureStringNonNull(associated_data);

  uint64_t associated_data_size_in_bytes = associated_data.size();
  uint64_t associated_data_size_in_bits = associated_data_size_in_bytes * 8;
  if (associated_data_size_in_bits / 8 !=
      associated_data_size_in_bytes /* overflow occured! */) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "additional data too long");
  }

  auto ct = ind_cpa_cipher_->Encrypt(plaintext);
  if (!ct.ok()) {
    return ct.status();
  }
  std::string ciphertext(ct.value());
  std::string toAuthData =
      absl::StrCat(associated_data, ciphertext,
                   longToBigEndianStr(associated_data_size_in_bits));

  auto tag = mac_->ComputeMac(toAuthData);
  if (!tag.ok()) {
    return tag.status();
  }
  if (tag.value().size() != tag_size_) {
    return util::Status(absl::StatusCode::kInternal, "invalid tag size");
  }
  return ciphertext.append(tag.value());
}

util::StatusOr<std::string> EncryptThenAuthenticate::Decrypt(
    absl::string_view ciphertext, absl::string_view associated_data) const {
  // BoringSSL expects a non-null pointer for associated_data,
  // regardless of whether the size is 0.
  associated_data = internal::EnsureStringNonNull(associated_data);

  if (ciphertext.size() < tag_size_) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "ciphertext too short");
  }

  uint64_t associated_data_size_in_bytes = associated_data.size();
  uint64_t associated_data_size_in_bits = associated_data_size_in_bytes * 8;
  if (associated_data_size_in_bits / 8 !=
      associated_data_size_in_bytes /* overflow occured! */) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "additional data too long");
  }

  auto payload = ciphertext.substr(0, ciphertext.size() - tag_size_);
  auto tag = ciphertext.substr(ciphertext.size() - tag_size_, tag_size_);
  std::string toAuthData =
      absl::StrCat(associated_data, payload,
                   longToBigEndianStr(associated_data_size_in_bits));

  auto verified = mac_->VerifyMac(tag, toAuthData);
  if (!verified.ok()) {
    return verified;
  }

  auto pt = ind_cpa_cipher_->Decrypt(payload);
  if (!pt.ok()) {
    return pt.status();
  }

  return pt.value();
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
