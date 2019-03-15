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

#include "tink/subtle/aes_gcm_hkdf_stream_segment_encrypter.h"

#include <limits>
#include <string>
#include <vector>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/subtle/random.h"
#include "tink/subtle/stream_segment_encrypter.h"
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

const int AesGcmHkdfStreamSegmentEncrypter::kNonceSizeInBytes;
const int AesGcmHkdfStreamSegmentEncrypter::kNoncePrefixSizeInBytes;
const int AesGcmHkdfStreamSegmentEncrypter::kTagSizeInBytes;

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

util::Status Validate(const AesGcmHkdfStreamSegmentEncrypter::Params& params) {
  if (params.key_value.size() != 16 && params.key_value.size() != 32) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "key_value must have 16 or 32 bytes");
  }
  if (params.key_value.size() != params.salt.size()) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "salt must have same size as key_value");
  }
  if (params.first_segment_offset < 0) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "first_segment_offset must be non-negative");
  }
  int header_size = 1 + params.salt.size() +
                    AesGcmHkdfStreamSegmentEncrypter::kNoncePrefixSizeInBytes;
  if (params.ciphertext_segment_size <
      params.first_segment_offset + header_size +
      AesGcmHkdfStreamSegmentEncrypter::kTagSizeInBytes) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "ciphertext_segment_size too small");
  }
  return util::OkStatus();
}

util::Status AesGcmHkdfStreamSegmentEncrypter::InitCtx(
    absl::string_view key_value) {
  const EVP_AEAD* aead = GetAeadForKeySize(key_value.size());
  if (aead == nullptr) {
    return util::Status(util::error::INTERNAL, "invalid key size");
  }
  if (EVP_AEAD_CTX_init(
          ctx_.get(), aead, reinterpret_cast<const uint8_t*>(key_value.data()),
          key_value.size(), kTagSizeInBytes, nullptr) != 1) {
    return util::Status(util::error::INTERNAL,
                        "could not initialize EVP_AEAD_CTX");
  }
  return util::OkStatus();
}

int AesGcmHkdfStreamSegmentEncrypter::get_plaintext_segment_size() const {
  return ciphertext_segment_size_ - kTagSizeInBytes;
}

// static
util::StatusOr<std::unique_ptr<StreamSegmentEncrypter>>
    AesGcmHkdfStreamSegmentEncrypter::New(const Params& params) {
  auto status = Validate(params);
  if (!status.ok()) return status;

  std::unique_ptr<AesGcmHkdfStreamSegmentEncrypter>
      encrypter(new AesGcmHkdfStreamSegmentEncrypter());
  status = encrypter->InitCtx(params.key_value);
  if (!status.ok()) return status;
  uint8_t header_size =
      static_cast<uint8_t>(1 + params.salt.size() + kNoncePrefixSizeInBytes);
  encrypter->ciphertext_offset_ = header_size + params.first_segment_offset;
  encrypter->ciphertext_segment_size_ = params.ciphertext_segment_size;
  encrypter->nonce_prefix_ = Random::GetRandomBytes(kNoncePrefixSizeInBytes);
  encrypter->header_.resize(header_size);
  encrypter->header_[0] = header_size;
  memcpy(encrypter->header_.data() + 1, params.salt.data(), params.salt.size());
  memcpy(encrypter->header_.data() + 1 + params.salt.size(),
         encrypter->nonce_prefix_.data(), encrypter->nonce_prefix_.size());
  return {std::move(encrypter)};
}

util::Status AesGcmHkdfStreamSegmentEncrypter::EncryptSegment(
    const std::vector<uint8_t>& plaintext,
    bool is_last_segment,
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

  int ct_size = plaintext.size() + kTagSizeInBytes;
  ciphertext_buffer->resize(ct_size);

  // Construct IV.
  std::vector<uint8_t> iv(kNonceSizeInBytes);
  memcpy(iv.data(), nonce_prefix_.data(), kNoncePrefixSizeInBytes);
  BigEndianStore32(iv.data() + kNoncePrefixSizeInBytes,
                   static_cast<uint32_t>(get_segment_number()));
  iv.back() = is_last_segment ? 1 : 0;
  size_t out_len;
  if (!EVP_AEAD_CTX_seal(
          ctx_.get(), ciphertext_buffer->data(), &out_len,
          ciphertext_buffer->size(),
          iv.data(), iv.size(),
          plaintext.data(), plaintext.size(),
          /* ad = */ nullptr, /* ad.length() = */ 0)) {
    return util::Status(util::error::INTERNAL,
                        absl::StrCat("Encryption failed: ",
                                     SubtleUtilBoringSSL::GetErrors()));
  }
  IncSegmentNumber();
  return util::OkStatus();
}


}  // namespace subtle
}  // namespace tink
}  // namespace crypto
