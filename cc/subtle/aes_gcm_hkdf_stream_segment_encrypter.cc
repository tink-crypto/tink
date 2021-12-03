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

#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <utility>

#include "absl/algorithm/container.h"
#include "absl/base/config.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/aead/internal/ssl_aead.h"
#include "tink/internal/err_util.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

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

util::Status Validate(const AesGcmHkdfStreamSegmentEncrypter::Params& params) {
  if (params.key.size() != 16 && params.key.size() != 32) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "key must have 16 or 32 bytes");
  }
  if (params.key.size() != params.salt.size()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "salt must have same size as the key");
  }
  if (params.ciphertext_offset < 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "ciphertext_offset must be non-negative");
  }
  int header_size = 1 + params.salt.size() +
                    AesGcmHkdfStreamSegmentEncrypter::kNoncePrefixSizeInBytes;
  if (params.ciphertext_segment_size <=
      params.ciphertext_offset + header_size +
          AesGcmHkdfStreamSegmentEncrypter::kTagSizeInBytes) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "ciphertext_segment_size too small");
  }
  return util::OkStatus();
}

std::vector<uint8_t> CreateHeader(absl::string_view salt,
                                  absl::string_view nonce_prefix) {
  uint8_t header_size = static_cast<uint8_t>(
      1 + salt.size() +
      AesGcmHkdfStreamSegmentEncrypter::kNoncePrefixSizeInBytes);
  std::vector<uint8_t> header(header_size);
  header[0] = header_size;
  absl::c_copy(salt, header.begin() + 1);
  absl::c_copy(nonce_prefix, header.begin() + 1 + salt.size());
  return header;
}

// Constructs the nonce as | `nonce_prefix` | `segment_number` | 0 if
// `is_last_segment` or 1 |.
std::string ConstructNonce(absl::string_view nonce_prefix,
                           uint32_t segment_number, bool is_last_segment) {
  std::string iv;
  ResizeStringUninitialized(
      &iv, AesGcmHkdfStreamSegmentEncrypter::kNonceSizeInBytes);
  absl::c_copy(nonce_prefix, absl::MakeSpan(iv).begin());
  BigEndianStore32(
      reinterpret_cast<uint8_t*>(&iv[0]) +
          AesGcmHkdfStreamSegmentEncrypter::kNoncePrefixSizeInBytes,
      segment_number);
  iv.back() = is_last_segment ? 1 : 0;
  return iv;
}

}  // namespace

int AesGcmHkdfStreamSegmentEncrypter::get_plaintext_segment_size() const {
  return ciphertext_segment_size_ - kTagSizeInBytes;
}

AesGcmHkdfStreamSegmentEncrypter::AesGcmHkdfStreamSegmentEncrypter(
    std::unique_ptr<internal::SslOneShotAead> aead, const Params& params)
    : aead_(std::move(aead)),
      nonce_prefix_(Random::GetRandomBytes(kNoncePrefixSizeInBytes)),
      header_(CreateHeader(params.salt, nonce_prefix_)),
      ciphertext_segment_size_(params.ciphertext_segment_size),
      ciphertext_offset_(params.ciphertext_offset) {}

util::StatusOr<std::unique_ptr<StreamSegmentEncrypter>>
AesGcmHkdfStreamSegmentEncrypter::New(Params params) {
  util::Status status = Validate(params);
  if (!status.ok()) {
    return status;
  }
  util::StatusOr<std::unique_ptr<internal::SslOneShotAead>> aead =
      internal::CreateAesGcmOneShotCrypter(params.key);
  if (!aead.ok()) {
    return aead.status();
  }
  return {absl::WrapUnique(
      new AesGcmHkdfStreamSegmentEncrypter(*std::move(aead), params))};
}

util::Status AesGcmHkdfStreamSegmentEncrypter::EncryptSegment(
    const std::vector<uint8_t>& plaintext, bool is_last_segment,
    std::vector<uint8_t>* ciphertext_buffer) {
  if (plaintext.size() > get_plaintext_segment_size()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "plaintext too long");
  }
  if (ciphertext_buffer == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "ciphertext_buffer must be non-null");
  }
  if (get_segment_number() > std::numeric_limits<uint32_t>::max() ||
      (get_segment_number() == std::numeric_limits<uint32_t>::max() &&
       !is_last_segment)) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "too many segments");
  }

  const int64_t kCiphertextSize = plaintext.size() + kTagSizeInBytes;
  ciphertext_buffer->resize(kCiphertextSize);

  // Construct IV.
  std::string iv =
      ConstructNonce(nonce_prefix_, static_cast<uint32_t>(get_segment_number()),
                     is_last_segment);

  util::StatusOr<uint64_t> written_bytes = aead_->Encrypt(
      absl::string_view(reinterpret_cast<const char*>(plaintext.data()),
                        plaintext.size()),
      /*associated_data=*/absl::string_view(""), iv,
      absl::MakeSpan(reinterpret_cast<char*>(ciphertext_buffer->data()),
                     ciphertext_buffer->size()));

  if (!written_bytes.ok()) {
    return written_bytes.status();
  }

  IncSegmentNumber();
  return util::OkStatus();
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
