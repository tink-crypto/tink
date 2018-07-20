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

#include <memory>

#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "openssl/aes.h"
#include "openssl/evp.h"

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
      absl::string_view key_value, size_t nonce_size_in_bytes);

  crypto::tink::util::StatusOr<std::string> Encrypt(
      absl::string_view plaintext,
      absl::string_view additional_data) const override;

  crypto::tink::util::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext,
      absl::string_view additional_data) const override;

  virtual ~AesEaxBoringSsl() {}

 private:
  static const int TAG_SIZE = 16;
  static const int BLOCK_SIZE = 16;

  AesEaxBoringSsl() = delete;
  AesEaxBoringSsl(absl::string_view key_value, size_t nonce_size);

  // Returns whether key_size_in_bytes is a supported key size.
  static bool IsValidKeySize(size_t key_size_in_bytes);

  // Returns whether nonce_size_in_bytes is a supported size for the nonce.
  static bool IsValidNonceSize(size_t nonce_size_in_bytes);

  // Encrypts a single block with AES.
  void EncryptBlock(const uint8_t in[BLOCK_SIZE],
                    uint8_t out[BLOCK_SIZE]) const;

  // Pads a partial data block of size 0 <= len <= BLOCK_SIZE.
  void Pad(const uint8_t* data, int len,
           uint8_t padded_block[BLOCK_SIZE]) const;

  // Computes a Omac over blob.
  // tag is either 0, 1 or 2, depending over which value (nonce, aad, message)
  // the Omac is computed.
  // mac is the return value of the function.
  void Omac(
      absl::string_view blob,
      int tag,
      uint8_t mac[BLOCK_SIZE]) const;

  // This is the same function as above with the difference that the blob
  // is represented by a pointer and its length.
  void Omac(const uint8_t* data, size_t len, int tag, uint8_t mac[BLOCK_SIZE])
      const;

  // Encrypts or decrypts some data using CTR mode. N are 16 bytes, which
  // are the result of an OMAC computation over the nonce.
  // in are the bytes that are encrypted or decrypted. result is the
  // encrypted rsp. decrypted value. size determines the size of in and result.
  void CtrCrypt(
      const uint8_t N[BLOCK_SIZE],
      const uint8_t *in,
      uint8_t *result,
      size_t size) const;

  // TODO(bleichen): This class is immutable. But it seems difficult to
  //   declare these members const, because the constructor is not trivial.
  AES_KEY aeskey_;
  uint8_t B_[BLOCK_SIZE];
  uint8_t P_[BLOCK_SIZE];
  const std::string key_;
  const size_t nonce_size_;
  // Set by the constructor to true if the initialization was successful.
  // New() is the only method that needs to check is_initialized_, since
  // New() will never return an AesEaxBoringssl instance that is not
  // initialized.
  bool is_initialized_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_AES_EAX_BORINGSSL_H_
