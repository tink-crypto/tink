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

#ifndef TINK_SUBTLE_AES_EAX_AESNI_H_
#define TINK_SUBTLE_AES_EAX_AESNI_H_

#ifdef __SSE4_1__
#ifdef __AES__

#include <xmmintrin.h>

#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// This class implements AES-EAX on CPUs that support the AESNI instruction set
// (as well as SSE 4.1).
// Currently the implementation supports 128 and 256 bit keys and 96 or 128 bit
// nonces. AES-EAX allows arbitrary nonce sizes. Allowing only 96 or 128 bits
// is a tink specific restriction.
class AesEaxAesni : public Aead {
 public:
  static crypto::tink::util::StatusOr<std::unique_ptr<Aead>> New(
      absl::string_view key_value, size_t nonce_size_in_bytes);

  crypto::tink::util::StatusOr<std::string> Encrypt(
      absl::string_view plaintext,
      absl::string_view additional_data) const override;

  crypto::tink::util::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext,
      absl::string_view additional_data) const override;

  ~AesEaxAesni() {}

 protected:
  // The tag size is fixed for this implementation.
  // Using the full 128-bits of the tag allows an efficient verification.
  static const size_t TAG_SIZE = 16;
  static const size_t BLOCK_SIZE = 16;

  virtual bool RawEncrypt(
    absl::string_view nonce,
    absl::string_view in,
    absl::string_view additional_data,
    uint8_t *ciphertext,
    size_t ciphertext_size) const;

  virtual bool RawDecrypt(
    absl::string_view nonce,
    absl::string_view in,
    absl::string_view additional_data,
    uint8_t *plaintext,
    size_t plaintext_size) const;

 private:
  AesEaxAesni() {}

  // AesEaxAesni instances are immutable objects.
  // Therefore, the only place where SetKey should be called is in the
  // construction, i.e. in New().
  bool SetKey(absl::string_view key_value, size_t nonce_size_in_bytes);

  // Encrypt a single block.
  __m128i EncryptBlock(const __m128i block) const;

  // Encrypt 2 blocks with plain AES.
  void Encrypt2Blocks(
      const __m128i in0,
      const __m128i in1,
      __m128i *out0,
      __m128i *out1) const;

  // Encrypt 3 blocks and decrypts 1 block.
  // This is used to decrypt a ciphertext and verify the MAC concurrently.
  void Encrypt3Decrypt1(
      const __m128i in0,
      const __m128i in1,
      const __m128i in2,
      const __m128i in_dec,
      __m128i* out0,
      __m128i* out1,
      __m128i* out2,
      __m128i* out_dec) const;

  // Pads a partial block of size 1 .. 16.
  __m128i Pad(const uint8_t* data, int len) const;

  // Computes an OMAC.
  __m128i OMAC(absl::string_view blob, int tag) const;

  static const int kMaxRounds = 14;  // maximal number of rounds
  static const int kMaxRoundKeys = kMaxRounds + 1;  // max number of round keys
  __m128i round_key_[kMaxRoundKeys];
  __m128i round_dec_key_[kMaxRoundKeys];
  __m128i B_;  // Used for padding
  __m128i P_;  // Used for padding
  int rounds_;
  size_t nonce_size_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // __AES__
#endif  // __SSE4_1__
#endif  // TINK_SUBTLE_AES_EAX_AESNI_H_

