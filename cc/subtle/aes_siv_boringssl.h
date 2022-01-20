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

#ifndef TINK_SUBTLE_AES_SIV_BORINGSSL_H_
#define TINK_SUBTLE_AES_SIV_BORINGSSL_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/aes.h"
#include "tink/deterministic_aead.h"
#include "tink/internal/aes_util.h"
#include "tink/internal/fips_utils.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// AesSivBoringSsl is an implemenatation of AES-SIV-CMAC as defined in
// https://tools.ietf.org/html/rfc5297 .
// AesSivBoringSsl implements a deterministic encryption with additional
// data (i.e. the DeterministicAead interface). Hence the implementation
// below is restricted to one AD component.
//
// Thread safety: This class is thread safe and thus can be used
// concurrently.
//
// Security:
// =========
// Chatterjee, Menezes and Sarkar analyze AES-SIV in Section 5.1 of
// https://www.math.uwaterloo.ca/~ajmeneze/publications/tightness.pdf
// Their analysis shows that AES-SIV is susceptible to an attack in
// a multi-user setting. Concretely, if an attacker knows the encryption
// of a message m encrypted and authenticated with k different keys,
// then it is possible  to find one of the MAC keys in time 2^b / k
// where b is the size of the MAC key. A consequence of this attack
// is that 128-bit MAC keys give unsufficient security.
// Since 192-bit AES keys are not supported by tink for voodoo reasons
// and RFC 5297 only supports same size encryption and MAC keys this
// implies that keys must be 64 bytes (2*256 bits) long.
class AesSivBoringSsl : public DeterministicAead {
 public:
  static crypto::tink::util::StatusOr<std::unique_ptr<DeterministicAead>> New(
      const util::SecretData& key);

  crypto::tink::util::StatusOr<std::string> EncryptDeterministically(
      absl::string_view plaintext,
      absl::string_view additional_data) const override;

  crypto::tink::util::StatusOr<std::string> DecryptDeterministically(
      absl::string_view ciphertext,
      absl::string_view additional_data) const override;

  static bool IsValidKeySizeInBytes(size_t size) { return size == 64; }

  static constexpr crypto::tink::internal::FipsCompatibility kFipsStatus =
      crypto::tink::internal::FipsCompatibility::kNotFips;

 private:
  static constexpr size_t kBlockSize = internal::AesBlockSize();

  AesSivBoringSsl(util::SecretUniquePtr<AES_KEY> k1,
                  util::SecretUniquePtr<AES_KEY> k2)
      : k1_(std::move(k1)),
        k2_(std::move(k2)),
        cmac_k1_(ComputeCmacK1()),
        cmac_k2_(ComputeCmacK2()) {}

  // Precomputes cmac_k1
  util::SecretData ComputeCmacK1() const;
  // Precomputes cmac_k2
  util::SecretData ComputeCmacK2() const;

  // Encrypts a single block using k2_.
  // This is used for CMACs.
  void EncryptBlock(const uint8_t in[kBlockSize],
                    uint8_t out[kBlockSize]) const;

  // Computes a CMAC of some data.
  void Cmac(absl::Span<const uint8_t> data, uint8_t mac[kBlockSize]) const;

  // Computes CMAC(XorEnd(data, last)), where XorEnd
  // xors the bytes in last to the last bytes in data.
  // The size of the data must be at least 16 bytes.
  void CmacLong(absl::Span<const uint8_t> data, const uint8_t last[kBlockSize],
                uint8_t mac[kBlockSize]) const;

  // Multiplying an element in GF(2^128) by its generator.
  // This functions is incorrectly named "doubling" in section 2.3 of RFC 5297.
  static void MultiplyByX(uint8_t block[kBlockSize]);

  // Xors a block
  // res = x ^ y
  static void XorBlock(const uint8_t x[kBlockSize], const uint8_t y[kBlockSize],
                       uint8_t res[kBlockSize]);

  void S2v(absl::Span<const uint8_t> aad, absl::Span<const uint8_t> msg,
           uint8_t siv[kBlockSize]) const;

  // Encrypts (or decrypts) `in` using an SIV `siv` and key `key`, and writes
  // the result to `out`.
  util::Status AesCtrCrypt(absl::string_view in, const uint8_t siv[kBlockSize],
                           const AES_KEY* key, absl::Span<char> out) const;

  const util::SecretUniquePtr<AES_KEY> k1_;
  const util::SecretUniquePtr<AES_KEY> k2_;
  const util::SecretData cmac_k1_;
  const util::SecretData cmac_k2_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_AES_SIV_BORINGSSL_H_
