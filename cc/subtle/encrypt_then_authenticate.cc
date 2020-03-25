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

#include <string>
#include <vector>

#include "tink/aead.h"
#include "tink/mac.h"
#include "tink/subtle/ind_cpa_cipher.h"
#include "tink/subtle/subtle_util_boringssl.h"
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
    return util::Status(util::error::INVALID_ARGUMENT, "tag size too small");
  }
  std::unique_ptr<Aead> aead(new EncryptThenAuthenticate(
      std::move(ind_cpa_cipher), std::move(mac), tag_size));
  return std::move(aead);
}

util::StatusOr<std::string> EncryptThenAuthenticate::Encrypt(
    absl::string_view plaintext, absl::string_view additional_data) const {
  // BoringSSL expects a non-null pointer for plaintext and additional_data,
  // regardless of whether the size is 0.
  plaintext = SubtleUtilBoringSSL::EnsureNonNull(plaintext);
  additional_data = SubtleUtilBoringSSL::EnsureNonNull(additional_data);

  auto ct = ind_cpa_cipher_->Encrypt(plaintext);
  if (!ct.ok()) {
    return ct.status();
  }
  std::string ciphertext(ct.ValueOrDie());
  std::string toAuthData(additional_data);
  toAuthData.append(ciphertext);
  uint64_t aad_size_in_bits = additional_data.size() * 8;
  toAuthData.append(longToBigEndianStr(aad_size_in_bits));
  auto tag = mac_->ComputeMac(toAuthData);
  if (!tag.ok()) {
    return tag.status();
  }
  if (tag.ValueOrDie().size() != tag_size_) {
    return util::Status(util::error::INTERNAL, "invalid tag size");
  }
  return ciphertext.append(tag.ValueOrDie());
}

util::StatusOr<std::string> EncryptThenAuthenticate::Decrypt(
    absl::string_view ciphertext, absl::string_view additional_data) const {
  // BoringSSL expects a non-null pointer for additional_data,
  // regardless of whether the size is 0.
  additional_data = SubtleUtilBoringSSL::EnsureNonNull(additional_data);

  if (ciphertext.size() < tag_size_) {
    return util::Status(util::error::INVALID_ARGUMENT, "ciphertext too short");
  }

  std::string payload = std::string(ciphertext.data(), ciphertext.size())
                            .substr(0, ciphertext.size() - tag_size_);
  std::string toAuthData(additional_data);
  toAuthData.append(payload);
  uint64_t aad_size_in_bits = additional_data.size() * 8;
  toAuthData.append(longToBigEndianStr(aad_size_in_bits));
  auto verified = mac_->VerifyMac(
      ciphertext.substr(ciphertext.size() - tag_size_, tag_size_), toAuthData);
  if (!verified.ok()) {
    return verified;
  }

  auto pt = ind_cpa_cipher_->Decrypt(payload);
  if (!pt.ok()) {
    return pt.status();
  }

  return pt.ValueOrDie();
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
