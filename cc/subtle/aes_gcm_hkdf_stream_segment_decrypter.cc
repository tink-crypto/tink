// Copyright 2019 Google Inc.
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

#include "tink/subtle/aes_gcm_hkdf_stream_segment_decrypter.h"

#include <cstdint>
#include <cstring>
#include <limits>
#include <utility>

#include "absl/algorithm/container.h"
#include "absl/base/config.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/aead.h"
#include "tink/aead/internal/aead_util.h"
#include "tink/internal/err_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/aes_gcm_hkdf_stream_segment_encrypter.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/hkdf.h"
#include "tink/subtle/random.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {
namespace subtle {

namespace {

uint32_t ByteSwap(uint32_t val) {
  return ((val & 0xff000000) >> 24) | ((val & 0x00ff0000) >> 8) |
         ((val & 0x0000ff00) << 8) | ((val & 0x000000ff) << 24);
}

void BigEndianStore32(uint8_t dst[4], uint32_t val) {
#if defined(ABSL_IS_LITTLE_ENDIAN)
  val = ByteSwap(val);
#elif !defined(ABSL_IS_BIG_ENDIAN)
#error Unknown endianness
#endif
  std::memcpy(dst, &val, sizeof(val));
}

util::Status Validate(const AesGcmHkdfStreamSegmentDecrypter::Params& params) {
  if (!(params.hkdf_hash == SHA1 || params.hkdf_hash == SHA256 ||
        params.hkdf_hash == SHA512)) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "unsupported hkdf_hash");
  }
  if (params.derived_key_size != 16 && params.derived_key_size != 32) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "derived_key_size must be 16 or 32");
  }
  if (params.ikm.size() < 16 || params.ikm.size() < params.derived_key_size) {
    return util::Status(absl::StatusCode::kInvalidArgument, "ikm too small");
  }
  if (params.ciphertext_offset < 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "ciphertext_offset must be non-negative");
  }
  int header_size = 1 + params.derived_key_size +
                    AesGcmHkdfStreamSegmentEncrypter::kNoncePrefixSizeInBytes;
  if (params.ciphertext_segment_size <=
      params.ciphertext_offset + header_size +
          AesGcmHkdfStreamSegmentEncrypter::kTagSizeInBytes) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "ciphertext_segment_size too small");
  }
  return util::OkStatus();
}

}  // namespace

AesGcmHkdfStreamSegmentDecrypter::AesGcmHkdfStreamSegmentDecrypter(
    Params params)
    : ikm_(std::move(params.ikm)),
      hkdf_hash_(params.hkdf_hash),
      derived_key_size_(params.derived_key_size),
      ciphertext_offset_(params.ciphertext_offset),
      ciphertext_segment_size_(params.ciphertext_segment_size),
      associated_data_(std::move(params.associated_data)),
      header_size_(1 + derived_key_size_ +
                   AesGcmHkdfStreamSegmentEncrypter::kNoncePrefixSizeInBytes) {}

// static
util::StatusOr<std::unique_ptr<StreamSegmentDecrypter>>
AesGcmHkdfStreamSegmentDecrypter::New(Params params) {
  auto status = Validate(params);
  if (!status.ok()) return status;
  return {absl::WrapUnique(
      new AesGcmHkdfStreamSegmentDecrypter(std::move(params)))};
}

util::Status AesGcmHkdfStreamSegmentDecrypter::Init(
    const std::vector<uint8_t>& header) {
  if (is_initialized_) {
    return util::Status(absl::StatusCode::kFailedPrecondition,
                        "decrypter already initialized");
  }
  if (header.size() != header_size_) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("wrong header size, expected ", header_size_, " bytes"));
  }
  if (header[0] != header_size_) {
    return util::Status(absl::StatusCode::kInvalidArgument, "corrupted header");
  }

  // Extract salt and nonce_prefix.
  salt_.resize(derived_key_size_);
  nonce_prefix_.resize(
      AesGcmHkdfStreamSegmentEncrypter::kNoncePrefixSizeInBytes);
  absl::c_copy(absl::MakeSpan(header).subspan(1, derived_key_size_),
               salt_.begin());
  absl::c_copy(absl::MakeSpan(header).subspan(
                   1 + derived_key_size_,
                   AesGcmHkdfStreamSegmentEncrypter::kNoncePrefixSizeInBytes),
               nonce_prefix_.begin());

  // Derive symmetric key.
  auto hkdf_result = Hkdf::ComputeHkdf(
      hkdf_hash_, ikm_,
      absl::string_view(reinterpret_cast<const char*>(salt_.data()),
                        derived_key_size_),
      associated_data_, derived_key_size_);
  if (!hkdf_result.ok()) return hkdf_result.status();
  util::SecretData key = std::move(hkdf_result).ValueOrDie();

  // Initialize ctx_.
  util::StatusOr<const EVP_AEAD*> aead =
      internal::GetAesGcmAeadForKeySize(key.size());
  if (!aead.ok()) {
    return aead.status();
  }

  ctx_ = internal::SslUniquePtr<EVP_AEAD_CTX>(
      EVP_AEAD_CTX_new(*aead, key.data(), key.size(),
                       AesGcmHkdfStreamSegmentEncrypter::kTagSizeInBytes));
  if (!ctx_) {
    return util::Status(absl::StatusCode::kInternal,
                        "could not initialize EVP_AEAD_CTX");
  }
  is_initialized_ = true;
  return util::OkStatus();
}

int AesGcmHkdfStreamSegmentDecrypter::get_plaintext_segment_size() const {
  return ciphertext_segment_size_ -
         AesGcmHkdfStreamSegmentEncrypter::kTagSizeInBytes;
}

util::Status AesGcmHkdfStreamSegmentDecrypter::DecryptSegment(
    const std::vector<uint8_t>& ciphertext, int64_t segment_number,
    bool is_last_segment, std::vector<uint8_t>* plaintext_buffer) {
  if (!is_initialized_) {
    return util::Status(absl::StatusCode::kFailedPrecondition,
                        "decrypter not initialized");
  }
  if (ciphertext.size() > get_ciphertext_segment_size()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "ciphertext too long");
  }
  if (ciphertext.size() < AesGcmHkdfStreamSegmentEncrypter::kTagSizeInBytes) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "ciphertext too short");
  }
  if (plaintext_buffer == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "plaintext_buffer must be non-null");
  }
  if (segment_number > std::numeric_limits<uint32_t>::max() ||
      (segment_number == std::numeric_limits<uint32_t>::max() &&
       !is_last_segment)) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "too many segments");
  }

  int pt_size =
      ciphertext.size() - AesGcmHkdfStreamSegmentEncrypter::kTagSizeInBytes;
  plaintext_buffer->resize(pt_size);

  // Construct IV.
  std::vector<uint8_t> iv(AesGcmHkdfStreamSegmentEncrypter::kNonceSizeInBytes);
  absl::c_copy(nonce_prefix_, iv.begin());
  BigEndianStore32(
      iv.data() + AesGcmHkdfStreamSegmentEncrypter::kNoncePrefixSizeInBytes,
      static_cast<uint32_t>(segment_number));
  iv.back() = is_last_segment ? 1 : 0;

  // Decrypt.
  size_t out_len;
  if (!EVP_AEAD_CTX_open(ctx_.get(), plaintext_buffer->data(), &out_len,
                         plaintext_buffer->size(), iv.data(), iv.size(),
                         ciphertext.data(), ciphertext.size(),
                         /* ad = */ nullptr, /* ad.length() = */ 0)) {
    return util::Status(
        absl::StatusCode::kInternal,
        absl::StrCat("Decryption failed: ", internal::GetSslErrors()));
  }
  if (out_len != plaintext_buffer->size()) {
    return util::Status(absl::StatusCode::kInternal,
                        "incorrect plaintext size");
  }
  return util::OkStatus();
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
