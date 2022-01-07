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

#include <algorithm>
#include <cstdint>
#include <iterator>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/aes.h"
#include "openssl/crypto.h"
#include "tink/aead/internal/aead_util.h"
#include "tink/deterministic_aead.h"
#include "tink/internal/aes_util.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

crypto::tink::util::StatusOr<util::SecretUniquePtr<AES_KEY>> InitializeAesKey(
    absl::Span<const uint8_t> key) {
  util::SecretUniquePtr<AES_KEY> aes_key = util::MakeSecretUniquePtr<AES_KEY>();
  if (AES_set_encrypt_key(reinterpret_cast<const uint8_t*>(key.data()),
                          8 * key.size(), aes_key.get()) != 0) {
    return util::Status(absl::StatusCode::kInternal,
                        "could not initialize aes key");
  }
  return aes_key;
}

}  // namespace

// static
crypto::tink::util::StatusOr<std::unique_ptr<DeterministicAead>>
AesSivBoringSsl::New(const util::SecretData& key) {
  auto status = internal::CheckFipsCompatibility<AesSivBoringSsl>();
  if (!status.ok()) return status;

  if (!IsValidKeySizeInBytes(key.size())) {
    return util::Status(absl::StatusCode::kInvalidArgument, "invalid key size");
  }
  auto k1_or = InitializeAesKey(absl::MakeSpan(key).subspan(0, key.size() / 2));
  if (!k1_or.ok()) {
    return k1_or.status();
  }
  util::SecretUniquePtr<AES_KEY> k1 = std::move(k1_or).ValueOrDie();
  auto k2_or = InitializeAesKey(absl::MakeSpan(key).subspan(key.size() / 2));
  if (!k2_or.ok()) {
    return k2_or.status();
  }

  util::SecretUniquePtr<AES_KEY> k2 = std::move(k2_or).ValueOrDie();
  return {absl::WrapUnique(new AesSivBoringSsl(std::move(k1), std::move(k2)))};
}

util::SecretData AesSivBoringSsl::ComputeCmacK1() const {
  util::SecretData cmac_k1(kBlockSize, 0);
  EncryptBlock(cmac_k1.data(), cmac_k1.data());
  MultiplyByX(cmac_k1.data());
  return cmac_k1;
}

util::SecretData AesSivBoringSsl::ComputeCmacK2() const {
  util::SecretData cmac_k2(cmac_k1_);
  MultiplyByX(cmac_k2.data());
  return cmac_k2;
}

void AesSivBoringSsl::EncryptBlock(const uint8_t in[kBlockSize],
                                   uint8_t out[kBlockSize]) const {
  AES_encrypt(in, out, k1_.get());
}

// static
void AesSivBoringSsl::MultiplyByX(uint8_t block[kBlockSize]) {
  // Carry over 0x87 if msb is 1 0x00 if msb is 0.
  uint8_t carry = 0x87 & -(block[0] >> 7);
  for (size_t i = 0; i < kBlockSize - 1; ++i) {
    block[i] = (block[i] << 1) | (block[i + 1] >> 7);
  }
  block[kBlockSize - 1] =
      (block[kBlockSize - 1] << 1) ^ carry;
}

// static
void AesSivBoringSsl::XorBlock(const uint8_t x[kBlockSize],
                               const uint8_t y[kBlockSize],
                               uint8_t res[kBlockSize]) {
  for (int i = 0; i < kBlockSize; ++i) {
    res[i] = x[i] ^ y[i];
  }
}

void AesSivBoringSsl::Cmac(absl::Span<const uint8_t> data,
                           uint8_t mac[kBlockSize]) const {
  const size_t blocks =
      std::max(size_t{1}, (data.size() + kBlockSize - 1) / kBlockSize);
  const size_t last_block_idx = kBlockSize * (blocks - 1);
  const size_t last_block_size = data.size() - last_block_idx;
  uint8_t block[kBlockSize];
  std::fill(std::begin(block), std::end(block), 0);
  for (size_t idx = 0; idx < last_block_idx; idx += kBlockSize) {
    XorBlock(block, &data[idx], block);
    EncryptBlock(block, block);
  }
  for (size_t j = 0; j < last_block_size; j++) {
    block[j] ^= data[last_block_idx + j];
  }
  if (last_block_size == kBlockSize) {
    XorBlock(block, cmac_k1_.data(), block);
  } else {
    block[last_block_size] ^= 0x80;
    XorBlock(block, cmac_k2_.data(), block);
  }
  EncryptBlock(block, mac);
}

// Computes Cmac(XorEnd(data, last))
void AesSivBoringSsl::CmacLong(absl::Span<const uint8_t> data,
                               const uint8_t last[kBlockSize],
                               uint8_t mac[kBlockSize]) const {
  uint8_t block[kBlockSize];
  std::copy_n(data.begin(), kBlockSize, block);
  size_t idx = kBlockSize;
  while (kBlockSize <= data.size() - idx) {
    EncryptBlock(block, block);
    XorBlock(block, &data[idx], block);
    idx += kBlockSize;
  }
  size_t remaining = data.size() - idx;
  for (int j = 0; j < kBlockSize - remaining; ++j) {
    block[remaining + j] ^= last[j];
  }
  if (remaining == 0) {
    XorBlock(block, cmac_k1_.data(), block);
  } else {
    EncryptBlock(block, block);
    for (int j = 0; j < remaining; ++j) {
      block[j] ^= last[kBlockSize - remaining + j];
      block[j] ^= data[idx + j];
    }
    block[remaining] ^= 0x80;
    XorBlock(block, cmac_k2_.data(), block);
  }
  EncryptBlock(block, mac);
}

void AesSivBoringSsl::S2v(absl::Span<const uint8_t> aad,
                          absl::Span<const uint8_t> msg,
                          uint8_t siv[kBlockSize]) const {
  // This stuff could be precomputed.
  uint8_t block[kBlockSize];
  std::fill(std::begin(block), std::end(block), 0);
  Cmac(block, block);
  MultiplyByX(block);

  uint8_t aad_mac[kBlockSize];
  Cmac(aad, aad_mac);
  XorBlock(block, aad_mac, block);

  if (msg.size() >= kBlockSize) {
    CmacLong(msg, block, siv);
  } else {
    MultiplyByX(block);
    for (size_t i = 0; i < msg.size(); ++i) {
      block[i] ^= msg[i];
    }
    block[msg.size()] ^= 0x80;
    Cmac(block, siv);
  }
}

util::Status AesSivBoringSsl::AesCtrCrypt(absl::string_view in,
                                          const uint8_t siv[kBlockSize],
                                          const AES_KEY* key,
                                          absl::Span<char> out) const {
  uint8_t iv[kBlockSize];
  std::copy_n(siv, kBlockSize, iv);
  iv[8] &= 0x7f;
  iv[12] &= 0x7f;
  return internal::AesCtr128Crypt(in, iv, key, out);
}

util::StatusOr<std::string> AesSivBoringSsl::EncryptDeterministically(
    absl::string_view plaintext, absl::string_view additional_data) const {
  uint8_t siv[kBlockSize];
  S2v(absl::MakeSpan(reinterpret_cast<const uint8_t*>(additional_data.data()),
                     additional_data.size()),
      absl::MakeSpan(reinterpret_cast<const uint8_t*>(plaintext.data()),
                     plaintext.size()),
      siv);
  size_t ciphertext_size = plaintext.size() + kBlockSize;

  std::string ciphertext;
  ResizeStringUninitialized(&ciphertext, ciphertext_size);
  std::copy(std::begin(siv), std::end(siv), ciphertext.begin());
  util::Status res =
      AesCtrCrypt(plaintext, siv, k2_.get(),
                  absl::MakeSpan(ciphertext).subspan(kBlockSize));
  if (!res.ok()) {
    return res;
  }
  return ciphertext;
}

util::StatusOr<std::string> AesSivBoringSsl::DecryptDeterministically(
    absl::string_view ciphertext, absl::string_view additional_data) const {
  if (ciphertext.size() < kBlockSize) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "ciphertext too short");
  }
  size_t plaintext_size = ciphertext.size() - kBlockSize;
  std::string plaintext;
  ResizeStringUninitialized(&plaintext, plaintext_size);
  const uint8_t* siv = reinterpret_cast<const uint8_t*>(&ciphertext[0]);
  util::Status res = AesCtrCrypt(ciphertext.substr(kBlockSize), siv, k2_.get(),
                                 absl::MakeSpan(plaintext));
  if (!res.ok()) {
    return res;
  }

  uint8_t s2v[kBlockSize];
  S2v(absl::MakeSpan(reinterpret_cast<const uint8_t*>(additional_data.data()),
                     additional_data.size()),
      absl::MakeSpan(reinterpret_cast<const uint8_t*>(plaintext.data()),
                     plaintext_size),
      s2v);
  if (CRYPTO_memcmp(siv, s2v, kBlockSize) != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "invalid ciphertext");
  }
  return plaintext;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
