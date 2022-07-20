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

#include <array>
#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "tink/aead.h"
#include "tink/util/secret_data.h"
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
      const util::SecretData& key, size_t nonce_size_in_bytes);

  crypto::tink::util::StatusOr<std::string> Encrypt(
      absl::string_view plaintext,
      absl::string_view associated_data) const override;

  crypto::tink::util::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext,
      absl::string_view associated_data) const override;

 protected:
  // The tag size is fixed for this implementation.
  // Using the full 128-bits of the tag allows an efficient verification.
  static constexpr size_t kTagSize = 16;
  static constexpr size_t kBlockSize = 16;

  virtual bool RawEncrypt(absl::string_view nonce, absl::string_view in,
                          absl::string_view associated_data,
                          absl::Span<uint8_t> ciphertext) const;

  virtual bool RawDecrypt(absl::string_view nonce, absl::string_view in,
                          absl::string_view associated_data,
                          absl::Span<uint8_t> plaintext) const;

 private:
  explicit AesEaxAesni(size_t nonce_size) : nonce_size_(nonce_size) {}

  // AesEaxAesni instances are immutable objects.
  // Therefore, the only place where SetKey should be called is in the
  // construction, i.e. in New().
  bool SetKey(const util::SecretData& key);

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

  static constexpr int kMaxRounds = 14;  // maximal number of rounds
  static constexpr int kMaxRoundKeys =
      kMaxRounds + 1;  // max number of round keys
  using RoundKeys = std::array<__m128i, kMaxRoundKeys>;
  util::SecretUniquePtr<RoundKeys> round_key_ =
      util::MakeSecretUniquePtr<RoundKeys>();
  util::SecretUniquePtr<RoundKeys> round_dec_key_ =
      util::MakeSecretUniquePtr<RoundKeys>();
  util::SecretUniquePtr<__m128i> B_ =
      util::MakeSecretUniquePtr<__m128i>();  // Used for padding
  util::SecretUniquePtr<__m128i> P_ =
      util::MakeSecretUniquePtr<__m128i>();  // Used for padding
  int rounds_;
  const size_t nonce_size_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // __AES__
#endif  // __SSE4_1__
#endif  // TINK_SUBTLE_AES_EAX_AESNI_H_

