// Copyright 2019 Google LLC
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

#include "tink/subtle/aes_ctr_hmac_streaming.h"

#include <limits>
#include <string>
#include <vector>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/base.h"
#include "openssl/cipher.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/hkdf.h"
#include "tink/subtle/hmac_boringssl.h"
#include "tink/subtle/random.h"
#include "tink/subtle/stream_segment_decrypter.h"
#include "tink/subtle/stream_segment_encrypter.h"
#include "tink/subtle/subtle_util.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/errors.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

static std::string NonceForSegment(absl::string_view nonce_prefix,
                                   int64_t segment_number,
                                   bool is_last_segment) {
  return absl::StrCat(
      nonce_prefix, BigEndian32(segment_number),
      is_last_segment ? std::string(1, '\x01') : std::string(1, '\x00'),
      std::string(4, '\x00'));
}

static util::Status DeriveKeys(const util::SecretData& ikm, HashType hkdf_algo,
                               absl::string_view salt,
                               absl::string_view associated_data, int key_size,
                               util::SecretData* key_value,
                               util::SecretData* hmac_key_value) {
  int derived_key_material_size =
      key_size + AesCtrHmacStreaming::kHmacKeySizeInBytes;
  auto hkdf_result = Hkdf::ComputeHkdf(hkdf_algo, ikm, salt, associated_data,
                                       derived_key_material_size);
  if (!hkdf_result.ok()) return hkdf_result.status();
  util::SecretData key_material = std::move(hkdf_result.ValueOrDie());
  *key_value =
      util::SecretData(key_material.begin(), key_material.begin() + key_size);
  *hmac_key_value =
      util::SecretData(key_material.begin() + key_size, key_material.end());
  return util::OkStatus();
}

static util::Status Validate(const AesCtrHmacStreaming::Params& params) {
  if (params.ikm.size() < std::max(16, params.key_size)) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "input key material too small");
  }
  if (!(params.hkdf_algo == SHA1 || params.hkdf_algo == SHA256 ||
        params.hkdf_algo == SHA512)) {
    return util::Status(util::error::INVALID_ARGUMENT, "unsupported hkdf_algo");
  }
  if (params.key_size != 16 && params.key_size != 32) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "key_size must be 16 or 32");
  }
  int header_size =
      1 + params.key_size + AesCtrHmacStreaming::kNoncePrefixSizeInBytes;
  if (params.ciphertext_segment_size <=
      params.ciphertext_offset + header_size + params.tag_size) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "ciphertext_segment_size too small");
  }
  if (params.ciphertext_offset < 0) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "ciphertext_offset must be non-negative");
  }
  if (params.tag_size < 10) {
    return util::Status(util::error::INVALID_ARGUMENT, "tag_size too small");
  }
  if (!(params.tag_algo == SHA1 || params.tag_algo == SHA256 ||
        params.tag_algo == SHA512)) {
    return util::Status(util::error::INVALID_ARGUMENT, "unsupported tag_algo");
  }
  if ((params.tag_algo == SHA1 && params.tag_size > 20) ||
      (params.tag_algo == SHA256 && params.tag_size > 32) ||
      (params.tag_algo == SHA512 && params.tag_size > 64)) {
    return util::Status(util::error::INVALID_ARGUMENT, "tag_size too big");
  }

  return util::OkStatus();
}

// AesCtrHmacStreaming
// static
util::StatusOr<std::unique_ptr<AesCtrHmacStreaming>> AesCtrHmacStreaming::New(
    Params params) {
  auto status = internal::CheckFipsCompatibility<AesCtrHmacStreaming>();
  if (!status.ok()) return status;

  status = Validate(params);
  if (!status.ok()) return status;
  return {absl::WrapUnique(new AesCtrHmacStreaming(std::move(params)))};
}

// static
util::StatusOr<std::unique_ptr<StreamSegmentEncrypter>>
AesCtrHmacStreaming::NewSegmentEncrypter(
    absl::string_view associated_data) const {
  return AesCtrHmacStreamSegmentEncrypter::New(params_, associated_data);
}

// static
util::StatusOr<std::unique_ptr<StreamSegmentDecrypter>>
AesCtrHmacStreaming::NewSegmentDecrypter(
    absl::string_view associated_data) const {
  return AesCtrHmacStreamSegmentDecrypter::New(params_, associated_data);
}

// AesCtrHmacStreamSegmentEncrypter
static std::string MakeHeader(absl::string_view salt,
                              absl::string_view nonce_prefix) {
  uint8_t header_size =
      static_cast<uint8_t>(1 + salt.size() + nonce_prefix.size());
  return absl::StrCat(std::string(1, header_size), salt, nonce_prefix);
}

// static
util::StatusOr<std::unique_ptr<StreamSegmentEncrypter>>
AesCtrHmacStreamSegmentEncrypter::New(const AesCtrHmacStreaming::Params& params,
                                      absl::string_view associated_data) {
  auto status = Validate(params);
  if (!status.ok()) return status;

  std::string salt = Random::GetRandomBytes(params.key_size);
  std::string nonce_prefix =
      Random::GetRandomBytes(AesCtrHmacStreaming::kNoncePrefixSizeInBytes);
  std::string header = MakeHeader(salt, nonce_prefix);

  util::SecretData key_value;
  util::SecretData hmac_key_value;
  status = DeriveKeys(params.ikm, params.hkdf_algo, salt, associated_data,
                      params.key_size, &key_value, &hmac_key_value);
  if (!status.ok()) return status;

  auto cipher = SubtleUtilBoringSSL::GetAesCtrCipherForKeySize(params.key_size);
  if (cipher == nullptr) {
    return util::Status(util::error::INTERNAL, "invalid key size");
  }

  auto hmac_result = HmacBoringSsl::New(params.tag_algo, params.tag_size,
                                        std::move(hmac_key_value));
  if (!hmac_result.ok()) return hmac_result.status();
  auto mac = std::move(hmac_result.ValueOrDie());

  return {absl::WrapUnique(new AesCtrHmacStreamSegmentEncrypter(
      std::move(key_value), header, nonce_prefix,
      params.ciphertext_segment_size, params.ciphertext_offset, params.tag_size,
      cipher, std::move(mac)))};
}

util::Status AesCtrHmacStreamSegmentEncrypter::EncryptSegment(
    const std::vector<uint8_t>& plaintext, bool is_last_segment,
    std::vector<uint8_t>* ciphertext_buffer) {
  if (plaintext.size() > get_plaintext_segment_size()) {
    return util::Status(util::error::INVALID_ARGUMENT, "plaintext too long");
  }
  if (ciphertext_buffer == nullptr) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "ciphertext_buffer must be non-null");
  }
  if (get_segment_number() > std::numeric_limits<uint32_t>::max() ||
      (get_segment_number() == std::numeric_limits<uint32_t>::max() &&
       !is_last_segment)) {
    return util::Status(util::error::INVALID_ARGUMENT, "too many segments");
  }

  int ct_size = plaintext.size() + tag_size_;
  ciphertext_buffer->resize(ct_size);

  std::string nonce =
      NonceForSegment(nonce_prefix_, segment_number_, is_last_segment);

  // Encrypt.
  bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
  if (ctx.get() == nullptr) {
    return util::Status(util::error::INTERNAL,
                        "could not initialize EVP_CIPHER_CTX");
  }
  if (EVP_EncryptInit_ex(ctx.get(), cipher_, nullptr /* engine */,
                         reinterpret_cast<const uint8_t*>(key_value_.data()),
                         reinterpret_cast<const uint8_t*>(nonce.data())) != 1) {
    return util::Status(util::error::INTERNAL, "could not initialize ctx");
  }

  int out_len;
  if (EVP_EncryptUpdate(ctx.get(), ciphertext_buffer->data(), &out_len,
                        plaintext.data(), plaintext.size()) != 1) {
    return util::Status(util::error::INTERNAL, "encryption failed");
  }
  if (out_len != plaintext.size()) {
    return util::Status(util::error::INTERNAL, "incorrect ciphertext size");
  }

  // Add MAC tag.
  absl::string_view ciphertext_string(
      reinterpret_cast<const char*>(ciphertext_buffer->data()),
      plaintext.size());
  auto tag_result = mac_->ComputeMac(absl::StrCat(nonce, ciphertext_string));
  if (!tag_result.ok()) return tag_result.status();
  std::string tag = tag_result.ValueOrDie();
  memcpy(ciphertext_buffer->data() + plaintext.size(),
         reinterpret_cast<const uint8_t*>(tag.data()), tag_size_);

  IncSegmentNumber();
  return util::OkStatus();
}

// AesCtrHmacStreamSegmentDecrypter
// static
util::StatusOr<std::unique_ptr<StreamSegmentDecrypter>>
AesCtrHmacStreamSegmentDecrypter::New(const AesCtrHmacStreaming::Params& params,
                                      absl::string_view associated_data) {
  auto status = Validate(params);
  if (!status.ok()) return status;

  return {absl::WrapUnique(new AesCtrHmacStreamSegmentDecrypter(
      params.ikm, params.hkdf_algo, params.key_size, associated_data,
      params.ciphertext_segment_size, params.ciphertext_offset, params.tag_algo,
      params.tag_size))};
}

util::Status AesCtrHmacStreamSegmentDecrypter::Init(
    const std::vector<uint8_t>& header) {
  if (is_initialized_) {
    return util::Status(util::error::FAILED_PRECONDITION,
                        "decrypter alreday initialized");
  }
  if (header.size() != get_header_size()) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        absl::StrCat("wrong header size, expected ",
                                     get_header_size(), " bytes"));
  }
  if (header[0] != header.size()) {
    return util::Status(util::error::INVALID_ARGUMENT, "corrupted header");
  }

  // Extract salt and nonce prefix.
  std::string salt(reinterpret_cast<const char*>(header.data() + 1), key_size_);
  nonce_prefix_ =
      std::string(reinterpret_cast<const char*>(header.data() + 1 + key_size_),
                  AesCtrHmacStreaming::kNoncePrefixSizeInBytes);

  util::SecretData hmac_key_value;
  auto status = DeriveKeys(ikm_, hkdf_algo_, salt, associated_data_, key_size_,
                           &key_value_, &hmac_key_value);
  if (!status.ok()) return status;

  cipher_ = SubtleUtilBoringSSL::GetAesCtrCipherForKeySize(key_size_);
  if (cipher_ == nullptr) {
    return util::Status(util::error::INTERNAL, "invalid key size");
  }

  auto hmac_result =
      HmacBoringSsl::New(tag_algo_, tag_size_, std::move(hmac_key_value));
  if (!hmac_result.ok()) return hmac_result.status();
  mac_ = std::move(hmac_result.ValueOrDie());

  is_initialized_ = true;
  return util::OkStatus();
}

util::Status AesCtrHmacStreamSegmentDecrypter::DecryptSegment(
    const std::vector<uint8_t>& ciphertext, int64_t segment_number,
    bool is_last_segment, std::vector<uint8_t>* plaintext_buffer) {
  if (!is_initialized_) {
    return util::Status(util::error::FAILED_PRECONDITION,
                        "decrypter not initialized");
  }
  if (ciphertext.size() > get_ciphertext_segment_size()) {
    return util::Status(util::error::INVALID_ARGUMENT, "ciphertext too long");
  }
  if (ciphertext.size() < tag_size_) {
    return util::Status(util::error::INVALID_ARGUMENT, "ciphertext too short");
  }
  if (plaintext_buffer == nullptr) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "plaintext_buffer must be non-null");
  }
  if (segment_number > std::numeric_limits<uint32_t>::max() ||
      (segment_number == std::numeric_limits<uint32_t>::max() &&
       !is_last_segment)) {
    return util::Status(util::error::INVALID_ARGUMENT, "too many segments");
  }

  int pt_size = ciphertext.size() - tag_size_;
  plaintext_buffer->resize(pt_size);

  std::string nonce =
      NonceForSegment(nonce_prefix_, segment_number, is_last_segment);

  // Verify MAC tag.
  absl::string_view tag(
      reinterpret_cast<const char*>(ciphertext.data() + pt_size), tag_size_);
  absl::string_view ciphertext_string(
      reinterpret_cast<const char*>(ciphertext.data()), pt_size);
  auto status = mac_->VerifyMac(tag, absl::StrCat(nonce, ciphertext_string));
  if (!status.ok()) return status;

  // Decrypt.
  bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
  if (ctx.get() == nullptr) {
    return util::Status(util::error::INTERNAL,
                        "could not initialize EVP_CIPHER_CTX");
  }
  if (EVP_DecryptInit_ex(ctx.get(), cipher_, nullptr /* engine */,
                         reinterpret_cast<const uint8_t*>(key_value_.data()),
                         reinterpret_cast<const uint8_t*>(nonce.data())) != 1) {
    return util::Status(util::error::INTERNAL, "could not initialize ctx");
  }

  int out_len;
  if (EVP_DecryptUpdate(ctx.get(), plaintext_buffer->data(), &out_len,
                        ciphertext.data(), pt_size) != 1) {
    return util::Status(util::error::INTERNAL, "decryption failed");
  }
  if (out_len != pt_size) {
    return util::Status(util::error::INTERNAL, "incorrect plaintext size");
  }

  return util::OkStatus();
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
