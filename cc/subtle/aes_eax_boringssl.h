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

#ifndef TINK_SUBTLE_AES_EAX_BORINGSSL_H_
#define TINK_SUBTLE_AES_EAX_BORINGSSL_H_

#include <array>
#include <memory>

#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/aes.h"
#include "openssl/evp.h"
#include "tink/aead.h"
#include "tink/internal/fips_utils.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

class AesEaxBoringSsl : public Aead {
 public:
  // Constructs a new Aead cipher for Aes-EAX.
  // Currently supported key sizes are 128 and 256 bits.
  // Currently supported nonce sizes are 12 and 16 bytes.
  // The tag size is fixed to 16 bytes.
  static crypto::tink::util::StatusOr<std::unique_ptr<Aead>> New(
      const util::SecretData& key, size_t nonce_size_in_bytes);

  crypto::tink::util::StatusOr<std::string> Encrypt(
      absl::string_view plaintext,
      absl::string_view additional_data) const override;

  crypto::tink::util::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext,
      absl::string_view additional_data) const override;

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

 private:
  static constexpr int kTagSize = 16;
  static constexpr int kBlockSize = 16;

  using Block = std::array<uint8_t, kBlockSize>;

  AesEaxBoringSsl(util::SecretUniquePtr<AES_KEY> aeskey, size_t nonce_size)
      : aeskey_(std::move(aeskey)),
        nonce_size_(nonce_size),
        B_(ComputeB()),
        P_(ComputeP()) {}

  // Precomputes block B. Requires aeskey_ to be initialized.
  util::SecretData ComputeB() const;
  // Precomputes block P. Requires aeskey_ and B_ to be initialized.
  util::SecretData ComputeP() const;

  // Returns whether key_size_in_bytes is a supported key size.
  static bool IsValidKeySize(size_t key_size_in_bytes);

  // Returns whether nonce_size_in_bytes is a supported size for the nonce.
  static bool IsValidNonceSize(size_t nonce_size_in_bytes);

  // XORs block x with block y.
  // Result is: y = x ^ y
  static void XorBlock(const uint8_t x[kBlockSize], Block* y);

  // Multiplies in by X and stores result in out.
  static void MultiplyByX(const uint8_t in[kBlockSize],
                          uint8_t out[kBlockSize]);

  // Constant-time block equality
  static bool EqualBlocks(const uint8_t x[kBlockSize],
                          const uint8_t y[kBlockSize]);

  // Encrypts a single block with AES.
  void EncryptBlock(Block* block) const;
  void EncryptBlock(util::SecretData* block) const;

  // Pads a partial data block of size 0 <= len <= kBlockSize.
  Block Pad(absl::Span<const uint8_t> data) const;

  // Computes a Omac over blob.
  // tag is either 0, 1 or 2, depending over which value (nonce, aad, message)
  // the Omac is computed.
  Block Omac(absl::string_view blob, int tag) const;

  // This is the same function as above with the difference that the blob
  // is represented by a pointer and its length.
  Block Omac(absl::Span<const uint8_t> data, int tag) const;

  // Encrypts or decrypts some data using CTR mode. `N` is the 16 bytes result
  // of an OMAC computation over the nonce. `in` are the bytes that are
  // encrypted or decrypted, and the result is written to `out`. `in`.data()
  // MUST NOT be null.
  crypto::tink::util::Status CtrCrypt(const Block& N, absl::string_view in,
                                      absl::Span<char> out) const;

  const util::SecretUniquePtr<AES_KEY> aeskey_;
  const size_t nonce_size_;
  const util::SecretData B_;
  const util::SecretData P_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_AES_EAX_BORINGSSL_H_
