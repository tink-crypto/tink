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

#ifndef TINK_SUBTLE_AES_GCM_BORINGSSL_H_
#define TINK_SUBTLE_AES_GCM_BORINGSSL_H_

#include <memory>

#include "cc/aead.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "google/protobuf/stubs/stringpiece.h"
#include "openssl/evp.h"
#include "proto/common.pb.h"

namespace cloud {
namespace crypto {
namespace tink {

class AesGcmBoringSsl : public Aead {
 public:
  static util::StatusOr<std::unique_ptr<Aead>> New(
      const std::string& key_value);

  util::StatusOr<std::string> Encrypt(
      const google::protobuf::StringPiece& plaintext,
      const google::protobuf::StringPiece& additional_data) const override;

  util::StatusOr<std::string> Decrypt(
      const google::protobuf::StringPiece& ciphertext,
      const google::protobuf::StringPiece& additional_data) const override;

  virtual ~AesGcmBoringSsl() {}

 private:
  static const int IV_SIZE_IN_BYTES = 12;
  static const int TAG_SIZE_IN_BYTES = 16;

  AesGcmBoringSsl() {}
  AesGcmBoringSsl(const std::string& key_value, const EVP_CIPHER *cipher);

  const std::string key_;
  // cipher_ is a singleton owned by BoringSsl.
  // Preferable would be to use the AEAD interface, but unfortunately this
  // interface does not support 192-bit keys.
  // TODO(bleichen): We should find a way to deprecate OpenSSL, since the
  //   interfaces of this library are confusing and errorprone.
  const EVP_CIPHER *cipher_;
};

}  // namespace tink
}  // namespace crypto
}  // namespace cloud

#endif  // TINK_SUBTLE_AES_GCM_BORINGSSL_H_
