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

#include "tink/subtle/aes_ctr_hmac_stream_segment_encrypter.h"

#include <limits>
#include <string>
#include <vector>

#include "absl/memory/memory.h"
#include "openssl/base.h"
#include "openssl/cipher.h"
#include "openssl/err.h"
#include "openssl/evp.h"
#include "tink/subtle/hmac_boringssl.h"
#include "tink/subtle/random.h"
#include "tink/subtle/stream_segment_encrypter.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

const int AesCtrHmacStreamSegmentEncrypter::kNonceSizeInBytes;
const int AesCtrHmacStreamSegmentEncrypter::kNoncePrefixSizeInBytes;
const int AesCtrHmacStreamSegmentEncrypter::kHmacKeySizeInBytes;

static const EVP_CIPHER* GetCipherForKeySize(uint32_t size_in_bytes) {
  switch (size_in_bytes) {
    case 16:
      return EVP_aes_128_ctr();
    case 32:
      return EVP_aes_256_ctr();
    default:
      return nullptr;
  }
}

util::Status Validate(const AesCtrHmacStreamSegmentEncrypter::Params& params) {
  if (params.key_value.size() != 16 && params.key_value.size() != 32) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "key_value must have 16 or 32 bytes");
  }
  if (params.key_value.size() != params.salt.size()) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "salt must have same size as key_value");
  }
  if (params.ciphertext_offset < 0) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "ciphertext_offset must be non-negative");
  }
  int header_size = 1 + params.salt.size() +
                    AesCtrHmacStreamSegmentEncrypter::kNoncePrefixSizeInBytes;
  if (params.ciphertext_segment_size <=
      params.ciphertext_offset + header_size + params.tag_size) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "ciphertext_segment_size too small");
  }

  if (params.hmac_key_value.size() !=
      AesCtrHmacStreamSegmentEncrypter::kHmacKeySizeInBytes) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "invalid hmac_key_value size");
  }
  if (params.tag_size < 10) {
    return util::Status(util::error::INVALID_ARGUMENT, "tag size too small");
  }
  if (!(params.tag_algo == SHA1 || params.tag_algo == SHA256 ||
        params.tag_algo == SHA512)) {
    return util::Status(util::error::INVALID_ARGUMENT, "unsupported hash algo");
  }
  if ((params.tag_algo == SHA1 && params.tag_size > 20) ||
      (params.tag_algo == SHA256 && params.tag_size > 32) ||
      (params.tag_algo == SHA512 && params.tag_size > 64)) {
    return util::Status(util::error::INVALID_ARGUMENT, "tag size too big");
  }

  return util::OkStatus();
}

static std::vector<uint8_t> MakeHeader(const std::string& salt,
                                       const std::string& nonce_prefix) {
  uint8_t header_size =
      static_cast<uint8_t>(1 + salt.size() + nonce_prefix.size());
  std::vector<uint8_t> header(header_size);
  header[0] = header_size;
  memcpy(header.data() + 1, salt.data(), salt.size());
  memcpy(header.data() + 1 + salt.size(), nonce_prefix.data(),
         nonce_prefix.size());
  return header;
}

int AesCtrHmacStreamSegmentEncrypter::get_plaintext_segment_size() const {
  return ciphertext_segment_size_ - tag_size_;
}

AesCtrHmacStreamSegmentEncrypter::AesCtrHmacStreamSegmentEncrypter(
    const std::string& key_value, const std::vector<uint8_t>& header,
    const std::string& nonce_prefix, int ciphertext_offset,
    int ciphertext_segment_size, int tag_size, const EVP_CIPHER* cipher,
    std::unique_ptr<Mac> mac)
    : key_value_(key_value),
      header_(header),
      nonce_prefix_(nonce_prefix),
      ciphertext_offset_(ciphertext_offset),
      ciphertext_segment_size_(ciphertext_segment_size),
      tag_size_(tag_size),
      cipher_(cipher),
      mac_(std::move(mac)),
      segment_number_(0) {}

// static
util::StatusOr<std::unique_ptr<StreamSegmentEncrypter>>
AesCtrHmacStreamSegmentEncrypter::New(const Params& params) {
  auto status = Validate(params);
  if (!status.ok()) return status;

  std::string nonce_prefix = Random::GetRandomBytes(kNoncePrefixSizeInBytes);
  auto header = MakeHeader(params.salt, nonce_prefix);

  auto cipher = GetCipherForKeySize(params.key_value.size());
  if (cipher == nullptr) {
    return util::Status(util::error::INTERNAL, "invalid key size");
  }

  auto hmac_result = HmacBoringSsl::New(params.tag_algo, params.tag_size,
                                        params.hmac_key_value);
  if (!hmac_result.ok()) return hmac_result.status();
  auto mac = std::move(hmac_result.ValueOrDie());

  return {absl::WrapUnique(new AesCtrHmacStreamSegmentEncrypter(
      params.key_value, header, nonce_prefix, params.ciphertext_offset,
      params.ciphertext_segment_size, params.tag_size, cipher,
      std::move(mac)))};
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

  // Construct nonce for the segment.
  std::vector<uint8_t> nonce(kNonceSizeInBytes, 0);
  memcpy(nonce.data(), nonce_prefix_.data(), kNoncePrefixSizeInBytes);
  BigEndianStore32(static_cast<uint32_t>(get_segment_number()),
                   nonce.data() + kNoncePrefixSizeInBytes);
  nonce[kNoncePrefixSizeInBytes + 4] = is_last_segment ? 1 : 0;

  // Encrypt.
  bssl::UniquePtr<EVP_CIPHER_CTX> ctx(EVP_CIPHER_CTX_new());
  if (ctx.get() == nullptr) {
    return util::Status(util::error::INTERNAL,
                        "could not initialize EVP_CIPHER_CTX");
  }
  if (EVP_EncryptInit_ex(ctx.get(), cipher_, nullptr /* engine */,
                         reinterpret_cast<const uint8_t*>(key_value_.data()),
                         nonce.data()) != 1) {
    return util::Status(util::error::INTERNAL, "could not initialize ctx");
  }

  int out_len;
  std::vector<uint8_t> ciphertext(plaintext.size());
  if (EVP_EncryptUpdate(ctx.get(), ciphertext.data(), &out_len,
                        plaintext.data(), plaintext.size()) != 1) {
    return util::Status(util::error::INTERNAL, "encryption failed");
  }
  if (out_len != plaintext.size()) {
    return util::Status(util::error::INTERNAL, "incorrect ciphertext size");
  }
  memcpy(ciphertext_buffer->data(), ciphertext.data(), ciphertext.size());

  // Add MAC tag.
  auto tag_result =
      mac_->ComputeMac(reinterpret_cast<const char*>(ciphertext.data()));
  if (!tag_result.ok()) return tag_result.status();
  std::string tag = tag_result.ValueOrDie();
  memcpy(ciphertext_buffer->data() + ciphertext.size(),
         reinterpret_cast<const uint8_t*>(tag.data()), tag_size_);

  IncSegmentNumber();
  return util::OkStatus();
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
