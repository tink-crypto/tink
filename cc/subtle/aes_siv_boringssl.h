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

#include "absl/strings/string_view.h"
#include "tink/deterministic_aead.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "openssl/aes.h"

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
  static crypto::tink::util::StatusOr<std::unique_ptr<DeterministicAead>>
  New(absl::string_view key_value);

  crypto::tink::util::StatusOr<std::string> EncryptDeterministically(
      absl::string_view plaintext,
      absl::string_view additional_data) const override;

  crypto::tink::util::StatusOr<std::string> DecryptDeterministically(
      absl::string_view ciphertext,
      absl::string_view additional_data) const override;

  virtual ~AesSivBoringSsl() {}

  static bool IsValidKeySizeInBytes(size_t size) {
    return size == 64;
  }

 private:
  static const size_t BLOCK_SIZE = 16;

  AesSivBoringSsl() {}

  // Sets the key and precomputes the sub keys of an instance.
  // This method must be used only in New().
  bool SetKey(absl::string_view key_value);

  // Encrypts (or decrypts) the bytes in in using an SIV and
  // writes the result to out.
  void CtrCrypt(const uint8_t siv[BLOCK_SIZE],
                const uint8_t *in, uint8_t *out,
                size_t size) const;
  // Encrypts a single block using k2_.
  // This is used for CMACs.

  void EncryptBlock(const uint8_t in[BLOCK_SIZE],
                    uint8_t out[BLOCK_SIZE]) const;

  // Computes a CMAC of some data.
  void Cmac(const uint8_t* data, size_t size,
            uint8_t mac[BLOCK_SIZE]) const;

  // Computes CMAC(XorEnd(data, last)), where XorEnd
  // xors the bytes in last to the last bytes in data.
  // The size of the data must be at least 16 bytes.
  void CmacLong(const uint8_t* data, size_t size,
                const uint8_t last[BLOCK_SIZE],
                uint8_t mac[BLOCK_SIZE]) const;

  // Multiplying an element in GF(2^128) by its generator.
  // This functions is incorrectly named "doubling" in section 2.3 of RFC 5297.
  static void MultiplyByX(uint8_t block[BLOCK_SIZE]);

  void S2v(const uint8_t* aad, size_t aad_size,
           const uint8_t* msg, size_t msg_size,
           uint8_t siv[BLOCK_SIZE]) const;
  AES_KEY k1_;
  AES_KEY k2_;
  uint8_t cmac_k1_[BLOCK_SIZE];
  uint8_t cmac_k2_[BLOCK_SIZE];
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_AES_CTR_BORINGSSL_H_
