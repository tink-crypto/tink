// Copyright 2019 Google LLC
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

#ifndef TINK_AEAD_KMS_ENVELOPE_AEAD_H_
#define TINK_AEAD_KMS_ENVELOPE_AEAD_H_

#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// An implementation of KMS Envelope AEAD encryption
// (https://cloud.google.com/kms/docs/data-encryption-keys).
//
// In envelope encryption user generates a data encryption key (DEK) locally,
// encrypts data with DEK, sends DEK to a KMS to be encrypted (with a key
// managed by KMS), and stores encrypted DEK with encrypted data; at a later
// point user can retrieve encrypted data and DEK, use KMS to decrypt DEK,
// and use decrypted DEK to decrypt the data.
//
// The ciphertext structure is as follows:
//  - Length of encrypted DEK: 4 bytes (big endian)
//  - Encrypted DEK: variable length that is equal to the value
//    specified in the last 4 bytes.
//  - AEAD payload: variable length.
class KmsEnvelopeAead : public Aead {
 public:
  static crypto::tink::util::StatusOr<std::unique_ptr<Aead>> New(
      const google::crypto::tink::KeyTemplate& dek_template,
      std::unique_ptr<Aead> remote_aead);

  crypto::tink::util::StatusOr<std::string> Encrypt(
      absl::string_view plaintext,
      absl::string_view associated_data) const override;

  crypto::tink::util::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext,
      absl::string_view associated_data) const override;

  ~KmsEnvelopeAead() override {}

 private:
  KmsEnvelopeAead(const google::crypto::tink::KeyTemplate& dek_template,
                  std::unique_ptr<Aead> remote_aead) :
      dek_template_(dek_template), remote_aead_(std::move(remote_aead)) {}

  google::crypto::tink::KeyTemplate dek_template_;
  std::unique_ptr<Aead> remote_aead_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_AEAD_KMS_ENVELOPE_AEAD_H_
