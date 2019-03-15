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

#include <limits>
#include <string>
#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/subtle/aes_gcm_hkdf_stream_segment_encrypter.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/hkdf.h"
#include "tink/subtle/random.h"
#include "tink/subtle/stream_segment_decrypter.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "openssl/aead.h"
#include "openssl/err.h"


namespace crypto {
namespace tink {
namespace subtle {

namespace {

void BigEndianStore32(uint8_t dst[8], uint32_t val) {
  dst[0] = (val >> 24) & 0xff;
  dst[1] = (val >> 16) & 0xff;
  dst[2] = (val >> 8) & 0xff;
  dst[3] = val & 0xff;
}

}  // namespace

static const EVP_AEAD* GetAeadForKeySize(uint32_t size_in_bytes) {
  switch (size_in_bytes) {
    case 16:
      return EVP_aead_aes_128_gcm();
    case 32:
      return EVP_aead_aes_256_gcm();
    default:
      return nullptr;
  }
}

util::Status Validate(const AesGcmHkdfStreamSegmentDecrypter::Params& params) {
  if (!(params.hkdf_hash == SHA1 || params.hkdf_hash == SHA256 ||
        params.hkdf_hash == SHA512)) {
    return util::Status(util::error::INVALID_ARGUMENT, "unsupported hkdf_hash");
  }
  if (params.derived_key_size != 16 && params.derived_key_size != 32) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "derived_key_size must be 16 or 32");
  }
  if (params.ikm.size() < 16 || params.ikm.size() < params.derived_key_size) {
    return util::Status(util::error::INVALID_ARGUMENT, "ikm too small");
  }
  if (params.first_segment_offset < 0) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "first_segment_offset must be non-negative");
  }
  int header_size = 1 + params.derived_key_size +
                    AesGcmHkdfStreamSegmentEncrypter::kNoncePrefixSizeInBytes;
  if (params.ciphertext_segment_size <
      params.first_segment_offset + header_size +
      AesGcmHkdfStreamSegmentEncrypter::kTagSizeInBytes) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "ciphertext_segment_size too small");
  }
  return util::OkStatus();
}

// static
util::StatusOr<std::unique_ptr<StreamSegmentDecrypter>>
    AesGcmHkdfStreamSegmentDecrypter::New(const Params& params) {
  auto status = Validate(params);
  if (!status.ok()) return status;

  std::unique_ptr<AesGcmHkdfStreamSegmentDecrypter>
      decrypter(new AesGcmHkdfStreamSegmentDecrypter());
  decrypter->ikm_ = params.ikm;
  decrypter->hkdf_hash_ = params.hkdf_hash;
  int header_size = 1 + params.derived_key_size +
                    AesGcmHkdfStreamSegmentEncrypter::kNoncePrefixSizeInBytes;
  decrypter->header_size_ = header_size;
  decrypter->ciphertext_offset_ = header_size + params.first_segment_offset;
  decrypter->ciphertext_segment_size_ = params.ciphertext_segment_size;
  decrypter->derived_key_size_ = params.derived_key_size;
  decrypter->associated_data_ = params.associated_data;
  decrypter->is_initialized_ = false;

  return {std::move(decrypter)};
}

util::Status AesGcmHkdfStreamSegmentDecrypter::Init(
    const std::vector<uint8_t>& header) {
  if (is_initialized_) {
    return util::Status(util::error::FAILED_PRECONDITION,
                        "decrypter already initialized");
  }
  if (header.size() != header_size_) {
    return util::Status(util::error::INVALID_ARGUMENT,
        absl::StrCat("wrong header size, expected ", header_size_, " bytes"));
  }
  if (header[0] != header_size_) {
    return util::Status(util::error::INVALID_ARGUMENT, "corrupted header");
  }

  // Extract salt and nonce_prefix.
  salt_.resize(derived_key_size_);
  nonce_prefix_.resize(
      AesGcmHkdfStreamSegmentEncrypter::kNoncePrefixSizeInBytes);
  memcpy(salt_.data(), header.data() + 1, derived_key_size_);
  memcpy(nonce_prefix_.data(), header.data() + 1 + derived_key_size_,
         AesGcmHkdfStreamSegmentEncrypter::kNoncePrefixSizeInBytes);

  // Derive symmetric key.
  auto hkdf_result = Hkdf::ComputeHkdf(
      hkdf_hash_, ikm_,
      std::string(reinterpret_cast<const char *>(salt_.data()), derived_key_size_),
      associated_data_, derived_key_size_);
  if (!hkdf_result.ok()) return hkdf_result.status();
  key_value_ = hkdf_result.ValueOrDie();

  // Initialize ctx_.
  const EVP_AEAD* aead = GetAeadForKeySize(key_value_.size());
  if (aead == nullptr) {
    return util::Status(util::error::INTERNAL, "invalid key size");
  }
  if (EVP_AEAD_CTX_init(ctx_.get(),
                        aead,
                        reinterpret_cast<const uint8_t*>(key_value_.data()),
                        key_value_.size(),
                        AesGcmHkdfStreamSegmentEncrypter::kTagSizeInBytes,
                        nullptr) != 1) {
    return util::Status(util::error::INTERNAL,
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
    const std::vector<uint8_t>& ciphertext,
    int64_t segment_number,
    bool is_last_segment,
    std::vector<uint8_t>* plaintext_buffer) {
  if (!is_initialized_) {
    return util::Status(util::error::FAILED_PRECONDITION,
                        "decrypter not initialized");
  }
  if (ciphertext.size() > get_ciphertext_segment_size()) {
    return util::Status(util::error::INVALID_ARGUMENT, "ciphertext too long");
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

  int pt_size =
      ciphertext.size() - AesGcmHkdfStreamSegmentEncrypter::kTagSizeInBytes;
  plaintext_buffer->resize(pt_size);

  // Construct IV.
  std::vector<uint8_t> iv(AesGcmHkdfStreamSegmentEncrypter::kNonceSizeInBytes);
  memcpy(iv.data(), nonce_prefix_.data(),
         AesGcmHkdfStreamSegmentEncrypter::kNoncePrefixSizeInBytes);
  BigEndianStore32(
      iv.data() + AesGcmHkdfStreamSegmentEncrypter::kNoncePrefixSizeInBytes,
      static_cast<uint32_t>(segment_number));
  iv.back() = is_last_segment ? 1 : 0;

  // Decrypt.
  size_t out_len;
  if (!EVP_AEAD_CTX_open(
          ctx_.get(), plaintext_buffer->data(), &out_len,
          plaintext_buffer->size(),
          iv.data(), iv.size(),
          ciphertext.data(), ciphertext.size(),
          /* ad = */ nullptr, /* ad.length() = */ 0)) {
    return util::Status(util::error::INTERNAL,
                        absl::StrCat("Decryption failed: ",
                                     SubtleUtilBoringSSL::GetErrors()));
  }
  return util::OkStatus();
}


}  // namespace subtle
}  // namespace tink
}  // namespace crypto
