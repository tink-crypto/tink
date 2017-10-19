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

#include "cc/subtle/encrypt_then_authenticate.h"

#include <string>
#include <vector>

#include "cc/aead.h"
#include "cc/mac.h"
#include "cc/subtle/ind_cpa_cipher.h"
#include "cc/util/errors.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "google/protobuf/stubs/stringpiece.h"

namespace util = crypto::tink::util;

namespace crypto {
namespace tink {

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
  if (tag_size < MIN_TAG_SIZE_IN_BYTES) {
    return util::Status(util::error::INTERNAL, "tag size too small");
  }
  std::unique_ptr<Aead> aead(new EncryptThenAuthenticate(
      std::move(ind_cpa_cipher), std::move(mac), tag_size));
  return std::move(aead);
}

util::StatusOr<std::string> EncryptThenAuthenticate::Encrypt(
    google::protobuf::StringPiece plaintext,
    google::protobuf::StringPiece additional_data) const {
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
    google::protobuf::StringPiece ciphertext,
    google::protobuf::StringPiece additional_data) const {
  if (ciphertext.size() < tag_size_) {
    return util::Status(util::error::INTERNAL, "ciphertext too short");
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

}  // namespace tink
}  // namespace crypto
