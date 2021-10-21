// Copyright 2018 Google Inc.
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

#ifdef __SSE4_1__
#ifdef __AES__

#include "tink/subtle/aes_eax_aesni.h"

#include <emmintrin.h>  // SSE2: used for _mm_sub_epi64 _mm_unpacklo_epi64 etc.
#include <smmintrin.h>  // SSE4: used for _mm_cmpeq_epi64
#include <tmmintrin.h>  // SSE3: used for _mm_shuffle_epi8
#include <wmmintrin.h>  // AES_NI instructions.
#include <xmmintrin.h>  // Datatype _mm128i

#include <algorithm>
#include <array>
#include <memory>
#include <string>

#include "absl/algorithm/container.h"
#include "tink/internal/util.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util.h"

namespace crypto {
namespace tink {
namespace subtle {

namespace {
inline bool EqualBlocks(__m128i x, __m128i y) {
  // Compare byte wise.
  // A byte in eq is 0xff if the corresponding byte in x and y are equal
  // and 0x00 if the corresponding byte in x and y are not equal.
  __m128i eq = _mm_cmpeq_epi8(x, y);
  // Extract the 16 most significant bits of each byte in eq.
  int bits = _mm_movemask_epi8(eq);
  return 0xFFFF == bits;
}

// Reverse the order of the bytes in x.
inline __m128i Reverse(__m128i x) {
  const __m128i reverse_order =
      _mm_set_epi32(0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f);
  return _mm_shuffle_epi8(x, reverse_order);
}

// Increment x by 1.
// This function assumes that the bytes of x are in little endian order.
// Hence before using the result in EAX the bytes must be reversed, since EAX
// requires a counter value in big endian order.
inline __m128i Increment(__m128i x) {
  const __m128i mask =
      _mm_set_epi32(0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff);
  // Determine which of the two 64-bit parts of x overflow.
  // The result is 0xff..ff if the corresponding integers overflows and 0
  // otherwise.
  __m128i carries = _mm_cmpeq_epi64(x, mask);  // SSE4
  // Move the least significant 64 carry bits into the most significant 64 bits
  // of diff and fill the least significant bits of diff with 0xff..ff.
  __m128i diff = _mm_unpacklo_epi64(mask, carries);
  // Use subtraction since the 64-bit parts that must be incremented contain
  // the value -1.
  return _mm_sub_epi64(x, diff);
}

// Add y to x.
// This assumes that x is in little endian order.
// So far I've not found a simple way to compute and add the carry using
// xmm instructions. However, optimizing this function is not important,
// since it is used just once during decryption.
inline __m128i Add(__m128i x, uint64 y) {
  // Convert to a vector of two uint64.
  uint64 vec[2];
  _mm_storeu_si128(reinterpret_cast<__m128i*>(vec), x);
  // Perform the addition on the vector.
  vec[0] += y;
  if (y > vec[0]) {
    vec[1]++;
  }
  // Convert back to xmm.
  return _mm_loadu_si128(reinterpret_cast<__m128i*>(vec));
}

// Decrement x by 1.
// This function assumes that the bytes of x are in little endian order.
// Hence before using the result in EAX the bytes must be reversed, since EAX
// requires a counter value in big endian order.
inline __m128i Decrement(__m128i x) {
  const __m128i zero = _mm_setzero_si128();
  // Moves lower 64 bit of x into higher 64 bits and set the lower 64 bits to 0.
  __m128i shifted = _mm_slli_si128(x, 8);
  // Determines whether the lower and upper parts must be decremented.
  // I.e. the lower 64 bits must always be decremented.
  // The upper 64 bits must be decremented if the lower 64 bits of x are 0.
  __m128i carries = _mm_cmpeq_epi64(shifted, zero);  // SSE4
  // Use add since _mm_cmpeq_epi64 returns -1 for 64-bit parts that are equal.
  return _mm_add_epi64(x, carries);
}

// Rotate a value by 32 bit to the left (assuming little endian order).
inline __m128i RotLeft32(__m128i value) {
  return _mm_shuffle_epi32(value, _MM_SHUFFLE(2, 1, 0, 3));
}

// Multiply a binary polynomial given in big endian order by x
// and reduce modulo x^128 + x^7 + x^2 + x + 1
inline __m128i MultiplyByX(__m128i value) {
  // Convert big endian to little endian.,
  value = Reverse(value);
  // Sets each dword to 0xffffffff if the most significant bit of the same
  // dword in value is set.
  __m128i msb = _mm_srai_epi32(value, 31);
  __m128i msb_rotated = RotLeft32(msb);
  // Determines the carries. If the most signigicant bit in value is set,
  // then this bit is reduced to x^7 + x^2 + x + 1
  // (which corresponds to the constant 0x87).
  __m128i carry = _mm_and_si128(msb_rotated, _mm_set_epi32(1, 1, 1, 0x87));
  __m128i res = _mm_xor_si128(_mm_slli_epi32(value, 1), carry);
  // Converts the result back to big endian order.
  return Reverse(res);
}

// Load block[0]..block[block_size-1] into the least significant bytes of
// a register and set the remaining bytes to 0. The efficiency of this function
// is not critical.
__m128i LoadPartialBlock(const uint8_t* block, size_t block_size) {
  std::array<uint8_t, 16> tmp;
  tmp.fill(0);
  std::copy_n(block, block_size, tmp.begin());
  return _mm_loadu_si128(reinterpret_cast<__m128i*>(tmp.data()));
}

// Store the block_size least significant bytes from value in
// block[0] .. block[block_size - 1]. The efficiency of this procedure is not
// critical.
void StorePartialBlock(uint8_t* block, size_t block_size, __m128i value) {
  std::array<uint8_t, 16> tmp;
  _mm_storeu_si128(reinterpret_cast<__m128i*>(tmp.data()), value);
  std::copy_n(tmp.begin(), block_size, block);
}

static const uint8_t kRoundConstant[11] =
    {0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};
// Returns the round constant for round i.
uint8_t Rcon(int round) {
  return kRoundConstant[round];
}

// Call the AESKEYGENASSIST operation on a 32-bit input.
// This performs a rotation and a substitution with an S-box.
// This implementation uses AESKEYGENASSIST to compute the result twice
// and checks that the two results match.
inline uint32 SubRot(uint32 tmp) {
  __m128i inp = _mm_set_epi32(0, 0, tmp, 0);
  __m128i out = _mm_aeskeygenassist_si128(inp, 0x00);
  return _mm_extract_epi32(out, 1);
}

// Apply the S-box to the 4 bytes in a word.
// This operation is used in the key expansion of 256-bit keys.
// This implementation computes the result twice and checks equality.
inline uint32 SubWord(uint32 tmp) {
  __m128i inp = _mm_set_epi32(0, 0, tmp, 0);
  __m128i out = _mm_aeskeygenassist_si128(inp, 0x00);
  return _mm_extract_epi32(out, 0);
}

// The following code uses a key expansion that closely follows FIPS 197.
// If necessary it is possible to unroll the loops.
void Aes128KeyExpansion(const uint8_t* key, __m128i *round_key) {
  const int Nk = 4;  // Number of words in the key
  const int Nb = 4;  // Number of words per round key
  const int Nr = 10;  // Number or rounds
  uint32 *w = reinterpret_cast<uint32*>(round_key);
  const uint32 *keywords = reinterpret_cast<const uint32*>(key);
  for (int i = 0; i < Nk; i++) {
    w[i] = keywords[i];
  }
  uint32 tmp = w[Nk - 1];
  for (int i = Nk; i < Nb * (Nr + 1); i++) {
    if (i % Nk == 0) {
      tmp = SubRot(tmp) ^ Rcon(i / Nk);
    }
    tmp ^= w[i - Nk];
    w[i] = tmp;
  }
}

void Aes256KeyExpansion(const uint8_t* key, __m128i *round_key) {
  const int Nk = 8;  // Number of words in the key
  const int Nb = 4;  // Number of words per round key
  const int Nr = 14;  // Number or rounds
  uint32 *w = reinterpret_cast<uint32*>(round_key);
  const uint32 *keywords = reinterpret_cast<const uint32*>(key);
  for (int i = 0; i < Nk; i++) {
    w[i] = keywords[i];
  }
  uint32 tmp = w[Nk - 1];
  for (int i = Nk; i < Nb * (Nr + 1); i++) {
    if (i % Nk == 0) {
      tmp = SubRot(tmp) ^ Rcon(i / Nk);
    } else if (i % 4 == 0) {
      tmp = SubWord(tmp);
    }
    tmp ^= w[i - Nk];
    w[i] = tmp;
  }
}

bool IsValidNonceSize(size_t nonce_size) {
  return nonce_size == 12 || nonce_size == 16;
}

bool IsValidKeySize(size_t key_size) {
  return key_size == 16 || key_size == 32;
}

}  // namespace

crypto::tink::util::StatusOr<std::unique_ptr<Aead>> AesEaxAesni::New(
    const util::SecretData& key, size_t nonce_size_in_bytes) {
  if (!IsValidKeySize(key.size())) {
    return util::Status(util::error::INVALID_ARGUMENT, "Invalid key size");
  }
  if (!IsValidNonceSize(nonce_size_in_bytes)) {
    return util::Status(util::error::INVALID_ARGUMENT, "Invalid nonce size");
  }
  auto eax = absl::WrapUnique(new AesEaxAesni(nonce_size_in_bytes));
  if (!eax->SetKey(key)) {
    return util::Status(util::error::INTERNAL, "Setting AES key failed");
  }
  return {std::move(eax)};
}

bool AesEaxAesni::SetKey(const util::SecretData& key) {
  size_t key_size = key.size();
  if (key_size == 16) {
    rounds_ = 10;
    Aes128KeyExpansion(key.data(), round_key_->data());
  } else if (key_size == 32) {
    rounds_ = 14;
    Aes256KeyExpansion(key.data(), round_key_->data());
  } else {
    return false;
  }
  // Determine the round keys for decryption.
  (*round_dec_key_)[0] = (*round_key_)[rounds_];
  (*round_dec_key_)[rounds_] = (*round_key_)[0];
  for (int i = 1; i < rounds_; i++) {
    (*round_dec_key_)[i] = _mm_aesimc_si128((*round_key_)[rounds_ - i]);
  }

  // Derive the paddings from the key.
  __m128i zero = _mm_setzero_si128();
  __m128i zero_encrypted = EncryptBlock(zero);
  *B_ = MultiplyByX(zero_encrypted);
  *P_ = MultiplyByX(*B_);
  return true;
}

inline void AesEaxAesni::Encrypt3Decrypt1(
    const __m128i in0,
    const __m128i in1,
    const __m128i in2,
    const __m128i in_dec,
    __m128i* out0,
    __m128i* out1,
    __m128i* out2,
    __m128i* out_dec) const {
  __m128i first_round = (*round_key_)[0];
  __m128i tmp0 = _mm_xor_si128(in0, first_round);
  __m128i tmp1 = _mm_xor_si128(in1, first_round);
  __m128i tmp2 = _mm_xor_si128(in2, first_round);
  __m128i tmp3 = _mm_xor_si128(in_dec, (*round_dec_key_)[0]);
  for (int i = 1; i < rounds_; i++){
    __m128i round_key = (*round_key_)[i];
    tmp0 = _mm_aesenc_si128(tmp0, round_key);
    tmp1 = _mm_aesenc_si128(tmp1, round_key);
    tmp2 = _mm_aesenc_si128(tmp2, round_key);
    tmp3 = _mm_aesdec_si128(tmp3, (*round_dec_key_)[i]);
  }
  __m128i last_round = (*round_key_)[rounds_];
  *out0 = _mm_aesenclast_si128(tmp0, last_round);
  *out1 = _mm_aesenclast_si128(tmp1, last_round);
  *out2 = _mm_aesenclast_si128(tmp2, last_round);
  *out_dec = _mm_aesdeclast_si128(tmp3, (*round_dec_key_)[rounds_]);
}

inline __m128i AesEaxAesni::EncryptBlock(__m128i block) const {
  __m128i tmp = _mm_xor_si128(block, (*round_key_)[0]);
  for (int i = 1; i < rounds_; i++){
    tmp = _mm_aesenc_si128(tmp, (*round_key_)[i]);
  }
  return _mm_aesenclast_si128(tmp, (*round_key_)[rounds_]);
}

inline void AesEaxAesni::Encrypt2Blocks(
    const __m128i in0, const __m128i in1, __m128i *out0, __m128i *out1) const {
  __m128i tmp0 = _mm_xor_si128(in0, (*round_key_)[0]);
  __m128i tmp1 = _mm_xor_si128(in1, (*round_key_)[0]);
  for (int i = 1; i < rounds_; i++){
    __m128i round_key = (*round_key_)[i];
    tmp0 = _mm_aesenc_si128(tmp0, round_key);
    tmp1 = _mm_aesenc_si128(tmp1, round_key);
  }
  __m128i last_round = (*round_key_)[rounds_];
  *out0 = _mm_aesenclast_si128(tmp0, last_round);
  *out1 = _mm_aesenclast_si128(tmp1, last_round);
}

__m128i AesEaxAesni::Pad(const uint8_t* data, int len) const {
  // CHECK(0 <= len && len <= kBlockSize);
  // TODO(bleichen): Is there a better way to load n bytes into a register
  std::array<uint8_t, kBlockSize> tmp;
  tmp.fill(0);
  std::copy_n(data, len, tmp.begin());
  if (len == kBlockSize) {
    __m128i block = _mm_loadu_si128(reinterpret_cast<__m128i*>(tmp.data()));
    return _mm_xor_si128(block, *B_);
  } else {
    tmp[len] = 0x80;
    __m128i block = _mm_loadu_si128(reinterpret_cast<__m128i*>(tmp.data()));
    return _mm_xor_si128(block, *P_);
  }
}

__m128i AesEaxAesni::OMAC(absl::string_view blob, int tag) const {
  const uint8_t* data = reinterpret_cast<const uint8_t*>(blob.data());
  size_t len = blob.size();
  __m128i state = _mm_set_epi32(tag << 24, 0, 0, 0);
  if (len == 0) {
    state = _mm_xor_si128(state, *B_);
  } else {
    state = EncryptBlock(state);
    size_t idx = 0;
    while (len - idx > kBlockSize) {
      __m128i in = _mm_loadu_si128((__m128i*) (data + idx));
      state = _mm_xor_si128(in, state);
      state = EncryptBlock(state);
      idx += kBlockSize;
    }
    state = _mm_xor_si128(state, Pad(data + idx, len - idx));
  }
  return EncryptBlock(state);
}

bool AesEaxAesni::RawEncrypt(absl::string_view nonce, absl::string_view in,
                             absl::string_view additional_data,
                             absl::Span<uint8_t> ciphertext) const {
  // Sanity check
  if (in.size() + kTagSize != ciphertext.size()) {
    return false;
  }
  const uint8_t* plaintext = reinterpret_cast<const uint8_t*>(in.data());

  // NOTE(bleichen): The author of EAX designed this mode, so that
  //   it would be possible to compute N and H independently of the encryption.
  //   So far this possiblity is not used in this implementation.
  const __m128i N = OMAC(nonce, 0);
  const __m128i H = OMAC(additional_data, 1);

  // Compute the initial counter in little endian order.
  // EAX uses big endian order, but it is easier to increment
  // a counter if it is in little endian order.
  __m128i ctr = Reverse(N);

  // Initialize mac with the header of the input for the MAC.
  __m128i mac = _mm_set_epi32(0x2000000, 0, 0, 0);

  uint8_t* out = ciphertext.data();
  size_t idx = 0;
  __m128i key_stream;
  while (idx + kBlockSize < in.size()) {
    __m128i ctr_big_endian = Reverse(ctr);
    // Get the key stream for one message block and compute
    // the MAC for the previous ciphertext block or header.
    Encrypt2Blocks(mac, ctr_big_endian, &mac, &key_stream);
    __m128i pt = _mm_loadu_si128(reinterpret_cast<const __m128i*>(plaintext));
    __m128i ct = _mm_xor_si128(pt, key_stream);
    mac = _mm_xor_si128(mac, ct);
    ctr = Increment(ctr);
    _mm_storeu_si128(reinterpret_cast<__m128i*>(out), ct);
    plaintext += kBlockSize;
    out += kBlockSize;
    idx += kBlockSize;
  }

  // Last block
  size_t last_block_size = in.size() - idx;
  if (last_block_size > 0) {
    __m128i ctr_big_endian = Reverse(ctr);
    Encrypt2Blocks(mac, ctr_big_endian, &mac, &key_stream);
    __m128i pt = LoadPartialBlock(plaintext, last_block_size);
    __m128i ct = _mm_xor_si128(pt, key_stream);
    StorePartialBlock(out, last_block_size, ct);
    __m128i padded_last_block = Pad(out, last_block_size);
    out += last_block_size;
    mac = _mm_xor_si128(mac, padded_last_block);
  } else {
    // Special code for plaintexts of size 0.
    mac = _mm_xor_si128(mac, *B_);
  }
  mac = EncryptBlock(mac);
  __m128i tag = _mm_xor_si128(mac, N);
  tag = _mm_xor_si128(tag, H);
  StorePartialBlock(out, kTagSize, tag);
  return true;
}

bool AesEaxAesni::RawDecrypt(absl::string_view nonce, absl::string_view in,
                             absl::string_view additional_data,
                             absl::Span<uint8_t> plaintext) const {
  __m128i N = OMAC(nonce, 0);
  __m128i H = OMAC(additional_data, 1);

  const uint8_t* ciphertext = reinterpret_cast<const uint8_t*>(in.data());
  const size_t ciphertext_size = in.size();

  // Sanity checks: RawDecrypt should always be called with valid sizes.
  if (ciphertext_size < kTagSize) {
    return false;
  }
  if (ciphertext_size - kTagSize != plaintext.size()) {
    return false;
  }

  // Get the tag from the ciphertext.
  const __m128i tag = _mm_loadu_si128(
      reinterpret_cast<const __m128i*>(&ciphertext[plaintext.size()]));

  // A CBC-MAC is reversible. This allows to pipeline the MAC verification
  // by recomputing the MAC for the first half of the ciphertext and
  // reversion the MAC for the second half.
  __m128i mac_forward = _mm_set_epi32(0x2000000, 0, 0, 0);
  __m128i mac_backward = _mm_xor_si128(tag, N);
  mac_backward = _mm_xor_si128(mac_backward, H);

  // Special case code for empty messages of size 0.
  if (plaintext.empty()) {
    mac_forward = _mm_xor_si128(mac_forward, *B_);
    mac_forward = EncryptBlock(mac_forward);
    return EqualBlocks(mac_forward, mac_backward);
  }

  const size_t last_block = (plaintext.size() - 1) / kBlockSize;
  const size_t last_block_size = ((plaintext.size() - 1) % kBlockSize) + 1;
  const __m128i* ciphertext_blocks =
      reinterpret_cast<const __m128i*>(ciphertext);
  __m128i* plaintext_blocks = reinterpret_cast<__m128i*>(plaintext.data());
  __m128i ctr_forward = Reverse(N);
  __m128i ctr_backward = Add(ctr_forward, last_block);
  __m128i unused = _mm_setzero_si128();
  __m128i stream_forward;
  __m128i stream_backward;
  Encrypt3Decrypt1(
      Reverse(ctr_backward), mac_forward, unused, mac_backward,
      &stream_backward, &mac_forward, &unused, &mac_backward);
  __m128i ct = LoadPartialBlock(&ciphertext[plaintext.size() - last_block_size],
                                last_block_size);
  __m128i pt = _mm_xor_si128(ct, stream_backward);
  StorePartialBlock(&plaintext[plaintext.size() - last_block_size],
                    last_block_size, pt);
  __m128i padded_last_block =
      Pad(&ciphertext[plaintext.size() - last_block_size], last_block_size);
  mac_backward = _mm_xor_si128(mac_backward, padded_last_block);
  const size_t mid_block = last_block / 2;
  // Decrypts two blocks concurrently as long as there are at least two
  // blocks to decrypt. The two blocks are the first block not yet decrypted
  // and the last block not yet decrypted. The reason for this is that the
  // OMAC can be verified at the same time. mac_forward is the OMAC of leading
  // ciphertext blocks that have already been decrypted. mac_backward is the
  // partial result for the OMAC up to block last_block - i - 1 that is
  // necessary so OMAC of the full encryption results in the tag received from
  // the ciphertext.
  for (size_t i = 0; i < mid_block; i++) {
    ctr_backward = Decrement(ctr_backward);
    __m128i ct_forward = _mm_loadu_si128(&ciphertext_blocks[i]);
    __m128i ct_backward =
        _mm_loadu_si128(&ciphertext_blocks[last_block - i - 1]);
    mac_forward = _mm_xor_si128(mac_forward, ct_forward);
    Encrypt3Decrypt1(
       Reverse(ctr_forward), Reverse(ctr_backward), mac_forward, mac_backward,
        &stream_forward, &stream_backward, &mac_forward, &mac_backward);
    __m128i plaintext_forward = _mm_xor_si128(ct_forward, stream_forward);
    __m128i plaintext_backward = _mm_xor_si128(ct_backward, stream_backward);
    _mm_storeu_si128(&plaintext_blocks[i], plaintext_forward);
    _mm_storeu_si128(&plaintext_blocks[last_block - i - 1], plaintext_backward);
    mac_backward = _mm_xor_si128(mac_backward, ct_backward);
    ctr_forward = Increment(ctr_forward);
  }
  // Decrypts and MACs another block, if there is a single block in the middle.
  if (last_block & 1) {
    __m128i ct = _mm_loadu_si128(&ciphertext_blocks[mid_block]);
    mac_forward = _mm_xor_si128(mac_forward, ct);
    Encrypt2Blocks(
        Reverse(ctr_forward), mac_forward, &stream_forward, &mac_forward);
    __m128i pt = _mm_xor_si128(ct, stream_forward);
    _mm_storeu_si128(&plaintext_blocks[mid_block], pt);
  }
  if (!EqualBlocks(mac_forward, mac_backward)) {
    absl::c_fill(plaintext, 0);
    return false;
  }
  return true;
}

crypto::tink::util::StatusOr<std::string> AesEaxAesni::Encrypt(
    absl::string_view plaintext, absl::string_view additional_data) const {
  // BoringSSL expects a non-null pointer for plaintext and additional_data,
  // regardless of whether the size is 0.
  plaintext = internal::EnsureStringNonNull(plaintext);
  additional_data = internal::EnsureStringNonNull(additional_data);

  if (SIZE_MAX - nonce_size_ - kTagSize <= plaintext.size()) {
    return util::Status(util::error::INVALID_ARGUMENT, "Plaintext too long");
  }
  size_t ciphertext_size = plaintext.size() + nonce_size_ + kTagSize;
  std::string ciphertext;
  ResizeStringUninitialized(&ciphertext, ciphertext_size);
  const std::string nonce = Random::GetRandomBytes(nonce_size_);
  absl::c_copy(nonce, ciphertext.begin());
  bool result = RawEncrypt(
      nonce, plaintext, additional_data,
      absl::MakeSpan(reinterpret_cast<uint8_t*>(&ciphertext[nonce_size_]),
                     ciphertext_size - nonce_size_));
  if (!result) {
    return util::Status(util::error::INTERNAL, "Encryption failed");
  }
  return ciphertext;
}

crypto::tink::util::StatusOr<std::string> AesEaxAesni::Decrypt(
    absl::string_view ciphertext, absl::string_view additional_data) const {
  // BoringSSL expects a non-null pointer for additional_data,
  // regardless of whether the size is 0.
  additional_data = internal::EnsureStringNonNull(additional_data);

  size_t ct_size = ciphertext.size();
  if (ct_size < nonce_size_ + kTagSize) {
    return util::Status(util::error::INVALID_ARGUMENT, "Ciphertext too short");
  }
  size_t out_size = ct_size - kTagSize - nonce_size_;
  absl::string_view nonce = ciphertext.substr(0, nonce_size_);
  absl::string_view encrypted =
      ciphertext.substr(nonce_size_, ct_size - nonce_size_);
  std::string res;
  ResizeStringUninitialized(&res, out_size);
  bool result = RawDecrypt(
      nonce, encrypted, additional_data,
      absl::MakeSpan(reinterpret_cast<uint8_t*>(&res[0]), res.size()));
  if (!result) {
    return util::Status(util::error::INTERNAL, "Decryption failed");
  }
  return res;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // __AES__
#endif  // __SSE4_1__


