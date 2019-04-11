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

#include "tink/aead/kms_envelope_aead.h"

#include <string>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/registry.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"


namespace crypto {
namespace tink {

namespace {

const int kEncryptedDekPrefixSize = 4;
const char* kEmptyAssociatedData = "";

void BigEndianStore32(uint8_t dst[4], uint32_t val) {
  dst[0] = (val >> 24) & 0xff;
  dst[1] = (val >> 16) & 0xff;
  dst[2] = (val >> 8) & 0xff;
  dst[3] = val & 0xff;
}

int32_t BigEndianLoad32(const uint8_t src[4]) {
  return static_cast<int32_t>(src[3])
      | (static_cast<int32_t>(src[2]) << 8)
      | (static_cast<int32_t>(src[1]) << 16)
      | (static_cast<int32_t>(src[0]) << 24);
}

// Constructs a ciphertext of KMS envelope encryption.
// The format of the ciphertext is the following:
//   4-byte-prefix | encrypted_dek | encrypted_plaintext
// where 4-byte-prefix is the length of encrypted_dek in big-endian format
// (for compatibility with Java)
std::string GetEnvelopeCiphertext(absl::string_view encrypted_dek,
                                  absl::string_view encrypted_plaintext) {
  uint8_t enc_dek_size[kEncryptedDekPrefixSize];
  BigEndianStore32(enc_dek_size, encrypted_dek.size());
  return absl::StrCat(
      std::string(reinterpret_cast<const char*>(enc_dek_size),
                  kEncryptedDekPrefixSize),
      encrypted_dek, encrypted_plaintext);
}

}  // namespace


// static
util::StatusOr<std::unique_ptr<Aead>> KmsEnvelopeAead::New(
      const google::crypto::tink::KeyTemplate& dek_template,
      std::unique_ptr<Aead> remote_aead) {
  if (remote_aead == nullptr) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "remote_aead must be non-null");
  }
  auto km_result = Registry::get_key_manager<Aead>(dek_template.type_url());
  if (!km_result.ok()) return km_result.status();
  std::unique_ptr<Aead> envelope_aead(
      new KmsEnvelopeAead(dek_template, std::move(remote_aead)));
  return std::move(envelope_aead);
}

util::StatusOr<std::string> KmsEnvelopeAead::Encrypt(
    absl::string_view plaintext, absl::string_view associated_data) const {
  // Generate DEK.
  auto dek_result = Registry::NewKeyData(dek_template_);
  if (!dek_result.ok()) return dek_result.status();
  auto dek = std::move(dek_result.ValueOrDie());

  // Wrap DEK with remote.
  auto dek_encrypt_result = remote_aead_->Encrypt(
      dek->SerializeAsString(), kEmptyAssociatedData);
  if (!dek_encrypt_result.ok()) return dek_encrypt_result.status();

  // Encrypt plaintext using DEK.
  auto aead_result = Registry::GetPrimitive<Aead>(*dek);
  if (!aead_result.ok()) return aead_result.status();
  auto aead = std::move(aead_result.ValueOrDie());
  auto encrypt_result = aead->Encrypt(plaintext, associated_data);
  if (!encrypt_result.ok()) return encrypt_result.status();

  // Build and return ciphertext.
  return GetEnvelopeCiphertext(dek_encrypt_result.ValueOrDie(),
                               encrypt_result.ValueOrDie());
}

util::StatusOr<std::string> KmsEnvelopeAead::Decrypt(
    absl::string_view ciphertext, absl::string_view associated_data) const {
  // Parse the ciphertext.
  if (ciphertext.size() < kEncryptedDekPrefixSize) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "ciphertext too short");
  }
  auto enc_dek_size = BigEndianLoad32(
      reinterpret_cast<const uint8_t*>(ciphertext.data()));
  if (enc_dek_size > ciphertext.size() - kEncryptedDekPrefixSize ||
      enc_dek_size < 0) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "invalid ciphertext");
  }
  // Decrypt the DEK with remote.
  auto dek_decrypt_result = remote_aead_->Decrypt(
      ciphertext.substr(kEncryptedDekPrefixSize, enc_dek_size),
      kEmptyAssociatedData);
  if (!dek_decrypt_result.ok()) {
    return util::Status(
        util::error::INVALID_ARGUMENT,
        absl::StrCat("invalid ciphertext: ",
                     dek_decrypt_result.status().error_message()));
  }

  // Create AEAD from DEK.
  google::crypto::tink::KeyData dek;
  if (!dek.ParseFromString(dek_decrypt_result.ValueOrDie())) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "invalid ciphertext");
  }

  // Encrypt plaintext using DEK.
  auto aead_result = Registry::GetPrimitive<Aead>(dek);
  if (!aead_result.ok()) return aead_result.status();
  auto aead = std::move(aead_result.ValueOrDie());
  return aead->Decrypt(
      ciphertext.substr(kEncryptedDekPrefixSize + enc_dek_size),
      associated_data);
}

}  // namespace tink
}  // namespace crypto
