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

#include "tink/subtle/aes_siv_boringssl.h"

#include <string>
#include <vector>

#include "tink/deterministic_aead.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "openssl/err.h"
#include "openssl/aes.h"

namespace crypto {
namespace tink {
namespace subtle {

static void XorBlock(
    const uint8_t x[16],
    const uint8_t y[16],
    uint8_t res[16]) {
  for (int i = 0; i < 16; i++) {
    res[i] = x[i] ^ y[i];
  }
}

// static
crypto::tink::util::StatusOr<std::unique_ptr<DeterministicAead>>
AesSivBoringSsl::New(absl::string_view key_value) {
  std::unique_ptr<AesSivBoringSsl> aes_siv(new AesSivBoringSsl());
  if (aes_siv->SetKey(key_value)) {
    return std::unique_ptr<DeterministicAead>(aes_siv.release());
  } else {
    return util::Status(util::error::INTERNAL, "invalid key size");
  }
}

bool AesSivBoringSsl::SetKey(absl::string_view key) {
  size_t key_size = key.size();
  if (!IsValidKeySizeInBytes(key_size)) {
    return false;
  }
  if (0 != AES_set_encrypt_key(
              reinterpret_cast<const uint8_t*>(key.data()),
              4 * key_size, &k1_)) {
    return false;
  }
  if (0 != AES_set_encrypt_key(
              reinterpret_cast<const uint8_t*>(key.data() + key_size / 2),
              4 * key_size, &k2_)) {
    return false;
  }
  uint8_t block[BLOCK_SIZE];
  memset(block, 0, BLOCK_SIZE);
  EncryptBlock(block, block);
  MultiplyByX(block);
  memcpy(cmac_k1_, block, BLOCK_SIZE);
  MultiplyByX(block);
  memcpy(cmac_k2_, block, BLOCK_SIZE);
  return true;
}

void AesSivBoringSsl::CtrCrypt(const uint8_t siv[BLOCK_SIZE],
                               const uint8_t *in, uint8_t *out,
                               size_t size) const {
  uint8_t iv[BLOCK_SIZE];
  memcpy(iv, siv, BLOCK_SIZE);
  iv[8] &= 0x7f;
  iv[12] &= 0x7f;
  unsigned int num = 0;
  uint8_t ecount_buf[BLOCK_SIZE];
  memset(ecount_buf, 0, BLOCK_SIZE);
  AES_ctr128_encrypt(in, out, size, &k2_, iv, ecount_buf, &num);
}

void AesSivBoringSsl::EncryptBlock(const uint8_t in[BLOCK_SIZE],
                                   uint8_t out[BLOCK_SIZE]) const {
  AES_encrypt(in, out, &k1_);
}

// static
void AesSivBoringSsl::MultiplyByX(uint8_t block[BLOCK_SIZE]) {
  uint8_t carry = block[0] >> 7;
  for (size_t i = 0; i < BLOCK_SIZE - 1; i++) {
    block[i] = (block[i] << 1) | (block[i+1] >> 7);
  }
  block[BLOCK_SIZE - 1 ] = (block[BLOCK_SIZE - 1] << 1) ^ (carry ? 0x87 : 0);
}

void AesSivBoringSsl::Cmac(const uint8_t* data, size_t size,
                           uint8_t mac[BLOCK_SIZE]) const {
  size_t blocks = (size + BLOCK_SIZE - 1) / BLOCK_SIZE;
  if (blocks == 0) {
    blocks = 1;
  }
  size_t last_block_size = size - BLOCK_SIZE * (blocks - 1);
  uint8_t block[BLOCK_SIZE];
  memset(block, 0, BLOCK_SIZE);
  size_t idx = 0;
  for (size_t i = 0; i < blocks - 1; i++) {
    XorBlock(block, &data[idx], block);
    EncryptBlock(block, block);
    idx += BLOCK_SIZE;
  }
  for (size_t j = 0; j < last_block_size; j++) {
    block[j] ^= data[idx + j];
  }
  if (last_block_size == BLOCK_SIZE) {
    XorBlock(block, cmac_k1_, block);
  } else {
    block[last_block_size] ^= 0x80;
    XorBlock(block, cmac_k2_, block);
  }
  EncryptBlock(block, mac);
}

// Computes Cmac(XorEnd(data, last))
void AesSivBoringSsl::CmacLong(
    const uint8_t* data, size_t size, const uint8_t last[BLOCK_SIZE],
    uint8_t mac[BLOCK_SIZE]) const {
  uint8_t block[BLOCK_SIZE];
  memcpy(block, data, BLOCK_SIZE);
  size_t idx = BLOCK_SIZE;
  while (BLOCK_SIZE <= size - idx) {
    EncryptBlock(block, block);
    XorBlock(block, &data[idx], block);
    idx += BLOCK_SIZE;
  }
  size_t remaining = size - idx;
  for (int j = 0; j < BLOCK_SIZE - remaining; ++j) {
    block[remaining + j] ^= last[j];
  }
  if (remaining == 0) {
    XorBlock(block, cmac_k1_, block);
  } else {
    EncryptBlock(block, block);
    for (int j = 0; j < remaining; ++j) {
      block[j] ^= last[BLOCK_SIZE - remaining + j];
      block[j] ^= data[idx + j];
    }
    block[remaining] ^= 0x80;
    XorBlock(block, cmac_k2_, block);
  }
  EncryptBlock(block, mac);
}

void AesSivBoringSsl::S2v(const uint8_t* aad, size_t aad_size,
                          const uint8_t* msg, size_t msg_size,
                          uint8_t siv[BLOCK_SIZE]) const {
  // This stuff could be precomputed.
  uint8_t block[BLOCK_SIZE];
  memset(block, 0, BLOCK_SIZE);
  Cmac(block, BLOCK_SIZE, block);
  MultiplyByX(block);

  uint8_t aad_mac[BLOCK_SIZE];
  Cmac(aad, aad_size, aad_mac);
  XorBlock(block, aad_mac, block);

  if (msg_size >= BLOCK_SIZE) {
    CmacLong(msg, msg_size, block, siv);
  } else {
    MultiplyByX(block);
    for (size_t i = 0; i < msg_size; i++) {
      block[i] ^= msg[i];
    }
    block[msg_size] ^= 0x80;
    Cmac(block, BLOCK_SIZE, siv);
  }
}

util::StatusOr<std::string> AesSivBoringSsl::EncryptDeterministically(
    absl::string_view plaintext,
    absl::string_view additional_data) const {
  uint8_t siv[BLOCK_SIZE];
  S2v(reinterpret_cast<const uint8_t*>(additional_data.data()),
      additional_data.size(),
      reinterpret_cast<const uint8_t*>(plaintext.data()),
      plaintext.size(),
      siv);
  size_t ciphertext_size = plaintext.size() + BLOCK_SIZE;
  std::vector<uint8_t> ct(ciphertext_size);
  memcpy(ct.data(), siv, BLOCK_SIZE);
  CtrCrypt(siv, reinterpret_cast<const uint8_t*>(plaintext.data()),
           ct.data() + BLOCK_SIZE, plaintext.size());
  return std::string(reinterpret_cast<const char*>(ct.data()), ciphertext_size);
}

util::StatusOr<std::string> AesSivBoringSsl::DecryptDeterministically(
    absl::string_view ciphertext,
    absl::string_view additional_data) const {
  if (ciphertext.size() < BLOCK_SIZE) {
    return util::Status(util::error::INVALID_ARGUMENT, "ciphertext too short");
  }
  size_t plaintext_size = ciphertext.size() - BLOCK_SIZE;
  std::vector<uint8_t> pt(plaintext_size);
  const uint8_t *siv = reinterpret_cast<const uint8_t*>(&ciphertext[0]);
  const uint8_t *ct = reinterpret_cast<const uint8_t*>(&ciphertext[BLOCK_SIZE]);
  CtrCrypt(siv, ct, pt.data(), plaintext_size);

  uint8_t s2v[BLOCK_SIZE];
  S2v(reinterpret_cast<const uint8_t*>(additional_data.data()),
      additional_data.size(), pt.data(), plaintext_size, s2v);
  // Compare the siv from the ciphertext with the recomputed siv
  uint8_t diff = 0;
  for (int i = 0; i < BLOCK_SIZE; ++i) {
    diff |= siv[i] ^ s2v[i];
  }
  if (diff != 0) {
    return util::Status(util::error::INVALID_ARGUMENT, "invalid ciphertext");
  }
  return std::string(reinterpret_cast<const char*>(pt.data()), plaintext_size);
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
