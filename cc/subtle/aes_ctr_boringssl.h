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

#ifndef TINK_SUBTLE_AES_CTR_BORINGSSL_H_
#define TINK_SUBTLE_AES_CTR_BORINGSSL_H_

#include <memory>

#include "cc/subtle/ind_cpa_cipher.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "google/protobuf/stubs/stringpiece.h"
#include "openssl/evp.h"

namespace crypto {
namespace tink {

class AesCtrBoringSsl : public IndCpaCipher {
 public:
  static crypto::tink::util::StatusOr<std::unique_ptr<IndCpaCipher>> New(
      google::protobuf::StringPiece key_value, uint8_t iv_size);

  crypto::tink::util::StatusOr<std::string> Encrypt(
      google::protobuf::StringPiece plaintext) const override;

  crypto::tink::util::StatusOr<std::string> Decrypt(
      google::protobuf::StringPiece ciphertext) const override;

  virtual ~AesCtrBoringSsl() {}

 private:
  static const uint8_t MIN_IV_SIZE_IN_BYTES = 12;
  static const uint8_t BLOCK_SIZE = 16;

  AesCtrBoringSsl() {}
  AesCtrBoringSsl(google::protobuf::StringPiece key_value, uint8_t iv_size,
                  const EVP_CIPHER *cipher);

  const std::string key_;
  uint8_t iv_size_;
  // cipher_ is a singleton owned by BoringSsl.
  const EVP_CIPHER *cipher_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_AES_CTR_BORINGSSL_H_
