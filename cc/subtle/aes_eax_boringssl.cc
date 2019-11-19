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

#include "tink/subtle/aes_eax_boringssl.h"

#include <string>
#include <vector>
#include <memory>

#include "openssl/err.h"
#include "openssl/evp.h"
#include "tink/aead.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

static const int BLOCK_SIZE = 16;

namespace {
// TODO(bleichen): There has to be a way to implement
//   the following routines fast. E.g. Clang 6.0.0 optimizes
//   Load64, Store64, BigendianLoad64, but does not optimize
//   BigEndianStore64.

// Loads and stores 8 bytes. The endianness of the two routines
// does not matter, as long as the two routines use the same order.
uint64_t Load64(const uint8_t src[8]) {
  uint64_t res;
  memmove(&res, src, 8);
  return res;
}

void Store64(uint8_t dst[8], uint64_t val) {
  memmove(dst, &val, 8);
}

uint64_t BigEndianLoad64(const uint8_t src[8]) {
  return static_cast<uint64_t>(src[7])
      | (static_cast<uint64_t>(src[6]) << 8)
      | (static_cast<uint64_t>(src[5]) << 16)
      | (static_cast<uint64_t>(src[4]) << 24)
      | (static_cast<uint64_t>(src[3]) << 32)
      | (static_cast<uint64_t>(src[2]) << 40)
      | (static_cast<uint64_t>(src[1]) << 48)
      | (static_cast<uint64_t>(src[0]) << 56);
}

void BigEndianStore64(uint8_t dst[8], uint64_t val) {
  dst[0] = (val >> 56) & 0xff;
  dst[1] = (val >> 48) & 0xff;
  dst[2] = (val >> 40) & 0xff;
  dst[3] = (val >> 32) & 0xff;
  dst[4] = (val >> 24) & 0xff;
  dst[5] = (val >> 16) & 0xff;
  dst[6] = (val >> 8) & 0xff;
  dst[7] = val & 0xff;
}

void XorBlock(const uint8_t x[BLOCK_SIZE],
              const uint8_t y[BLOCK_SIZE],
              uint8_t res[BLOCK_SIZE]) {
  uint64_t r0 = Load64(x) ^ Load64(y);
  uint64_t r1 = Load64(x + 8) ^ Load64(y + 8);
  Store64(res, r0);
  Store64(res + 8, r1);
}

void MultiplyByX(const uint8_t in[BLOCK_SIZE],
                 uint8_t out[BLOCK_SIZE]) {
  uint64_t in_high = BigEndianLoad64(in);
  uint64_t in_low = BigEndianLoad64(in + 8);
  uint64_t out_high = (in_high << 1) ^ (in_low >> 63);
  // If the most significant bit is set then the result has to
  // be reduced by x^128 + x^7 + x^4 + x^2 + x + 1.
  // The representation of x^7 + x^4 + x^2 + x + 1 is 0x87.
  uint64_t out_low = (in_low << 1) ^ (in_high >> 63 ? 0x87 : 0);
  BigEndianStore64(out, out_high);
  BigEndianStore64(out + 8, out_low);
}

bool EqualBlocks(const uint8_t x[BLOCK_SIZE],
                 const uint8_t y[BLOCK_SIZE]) {
  uint64_t res = Load64(x) ^ Load64(y);
  res |= Load64(x + 8) ^ Load64(y + 8);
  return res == 0;
}

}  // namespace

bool AesEaxBoringSsl::IsValidKeySize(size_t key_size_in_bytes) {
  return key_size_in_bytes == 16 ||
         key_size_in_bytes == 32;
}

bool AesEaxBoringSsl::IsValidNonceSize(size_t nonce_size_in_bytes) {
  return nonce_size_in_bytes == 12 ||
         nonce_size_in_bytes == 16;
}

AesEaxBoringSsl::AesEaxBoringSsl(
    absl::string_view key_value, size_t nonce_size)
    : nonce_size_(nonce_size) {
  int status = AES_set_encrypt_key(
      reinterpret_cast<const uint8_t*>(key_value.data()), key_value.size() * 8,
          &aeskey_);
  // status != 0 happens if key_value or aeskey_ is invalid. In both cases
  // this indicates a programming error.
  if (status != 0) {
    is_initialized_ = false;
    return;
  }
  uint8_t block[BLOCK_SIZE];
  memset(block, 0, BLOCK_SIZE);
  EncryptBlock(block, block);
  MultiplyByX(block, B_);
  MultiplyByX(B_, P_);
  is_initialized_ = true;
}

crypto::tink::util::StatusOr<std::unique_ptr<Aead>> AesEaxBoringSsl::New(
    absl::string_view key_value,
    size_t nonce_size_in_bytes) {
  if (!IsValidKeySize(key_value.size())) {
    return util::Status(util::error::INTERNAL, "Invalid key");
  }
  if (!IsValidNonceSize(nonce_size_in_bytes)) {
    return util::Status(util::error::INTERNAL, "Invalid nonce size");
  }
  std::unique_ptr<AesEaxBoringSsl> aead(
      new AesEaxBoringSsl(key_value, nonce_size_in_bytes));
  if (!aead->is_initialized_) {
    return util::Status(util::error::INTERNAL,
        "Could not initialize AesEaxBoringSsl");
  }
  return std::unique_ptr<Aead>(aead.release());
}

void AesEaxBoringSsl::Pad(const uint8_t* data, int len,
                          uint8_t padded_block[BLOCK_SIZE]) const {
  // TODO(bleichen): What are we using in tink to encode assertions?
  // The caller must ensure that data is no longer than a block.
  // CHECK(0 <= len && len <= BLOCK_SIZE) << "Invalid data size";
  memset(padded_block, 0, BLOCK_SIZE);
  memmove(padded_block, data, len);
  if (len == BLOCK_SIZE) {
    XorBlock(padded_block, B_, padded_block);
  } else {
    padded_block[len] = 0x80;
    XorBlock(padded_block, P_, padded_block);
  }
}

void AesEaxBoringSsl::EncryptBlock(const uint8_t in[BLOCK_SIZE],
                                   uint8_t out[BLOCK_SIZE]) const {
  AES_encrypt(in, out, &aeskey_);
}

void AesEaxBoringSsl::Omac(
    absl::string_view blob,
    int tag,
    uint8_t mac[BLOCK_SIZE]) const {
  Omac(reinterpret_cast<const uint8_t *>(blob.data()), blob.size(), tag, mac);
}

void AesEaxBoringSsl::Omac(const uint8_t* data,
                           size_t len,
                           int tag,
                           uint8_t mac[BLOCK_SIZE]) const {
  uint8_t block[BLOCK_SIZE];
  memset(block, 0, BLOCK_SIZE);
  block[15] = tag;
  if (len == 0) {
    XorBlock(block, B_, block);
    EncryptBlock(block, mac);
    return;
  }
  EncryptBlock(block, block);
  int idx = 0;
  while (len - idx > BLOCK_SIZE) {
    XorBlock(block, &data[idx], block);
    EncryptBlock(block, block);
    idx += BLOCK_SIZE;
  }
  uint8_t padded_block[BLOCK_SIZE];
  Pad(&data[idx], len - idx, padded_block);
  XorBlock(block, padded_block, block);
  EncryptBlock(block, mac);
}

void AesEaxBoringSsl::CtrCrypt(
    const uint8_t N[BLOCK_SIZE],
    const uint8_t *in,
    uint8_t *result,
    size_t size) const {
  // This special case is necessary to avoid problems when in == null.
  // in == null is possible since absl::string_view can contain null pointers.
  if (size == 0) {
    return;
  }
  // Make a copy of N, since BoringSsl changes ctr.
  uint8_t ctr[BLOCK_SIZE];
  memcpy(ctr, N, BLOCK_SIZE);
  unsigned int num = 0;
  uint8_t ecount_buf[BLOCK_SIZE];
  memset(ecount_buf, 0, BLOCK_SIZE);
  AES_ctr128_encrypt(in, result, size, &aeskey_, ctr, ecount_buf, &num);
}

crypto::tink::util::StatusOr<std::string> AesEaxBoringSsl::Encrypt(
    absl::string_view plaintext, absl::string_view additional_data) const {
  // BoringSSL expects a non-null pointer for plaintext and additional_data,
  // regardless of whether the size is 0.
  plaintext = SubtleUtilBoringSSL::EnsureNonNull(plaintext);
  additional_data = SubtleUtilBoringSSL::EnsureNonNull(additional_data);

  size_t ciphertext_size = plaintext.size() + nonce_size_ + TAG_SIZE;
  std::string ciphertext(ciphertext_size, '\0');
  uint8_t N[BLOCK_SIZE];
  const std::string nonce = Random::GetRandomBytes(nonce_size_);
  Omac(nonce, 0, N);
  uint8_t H[BLOCK_SIZE];
  Omac(additional_data, 1, H);
  uint8_t* ct_start = reinterpret_cast<uint8_t*>(&ciphertext[nonce_size_]);
  CtrCrypt(N, reinterpret_cast<const uint8_t*>(plaintext.data()),
              ct_start, plaintext.size());
  uint8_t mac[BLOCK_SIZE];
  Omac(ct_start, plaintext.size(), 2, mac);
  XorBlock(mac, N, mac);
  XorBlock(mac, H, mac);
  memmove(&ciphertext[0], nonce.data(), nonce_size_);
  memmove(&ciphertext[ciphertext_size - TAG_SIZE], mac, TAG_SIZE);
  return std::move(ciphertext);
}

crypto::tink::util::StatusOr<std::string> AesEaxBoringSsl::Decrypt(
    absl::string_view ciphertext, absl::string_view additional_data) const {
  // BoringSSL expects a non-null pointer for additional_data,
  // regardless of whether the size is 0.
  additional_data = SubtleUtilBoringSSL::EnsureNonNull(additional_data);

  size_t ct_size = ciphertext.size();
  if (ct_size < nonce_size_ + TAG_SIZE) {
    return util::Status(util::error::INTERNAL, "Ciphertext too short");
  }
  size_t out_size = ct_size - TAG_SIZE - nonce_size_;
  absl::string_view nonce = ciphertext.substr(0, nonce_size_);
  absl::string_view encrypted = ciphertext.substr(nonce_size_, out_size);
  absl::string_view tag = ciphertext.substr(ct_size - TAG_SIZE, TAG_SIZE);
  uint8_t N[BLOCK_SIZE];
  Omac(nonce, 0, N);
  uint8_t H[BLOCK_SIZE];
  Omac(additional_data, 1, H);
  uint8_t mac[BLOCK_SIZE];
  Omac(encrypted, 2, mac);
  XorBlock(mac, N, mac);
  XorBlock(mac, H, mac);
  const uint8_t *sig = reinterpret_cast<const uint8_t*>(tag.data());
  if (!EqualBlocks(mac, sig)) {
    return util::Status(util::error::INTERNAL, "Tag mismatch");
  }
  std::string res(out_size, '\0');
  CtrCrypt(N, reinterpret_cast<const uint8_t*>(encrypted.data()),
              reinterpret_cast<uint8_t*>(&res[0]), out_size);
  return std::move(res);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto


