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

#ifndef TINK_SUBTLE_AES_GCM_SIV_BORINGSSL_H_
#define TINK_SUBTLE_AES_GCM_SIV_BORINGSSL_H_

#include <memory>

#include "absl/strings/string_view.h"
#include "openssl/aead.h"
#include "tink/aead.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// AES-GCM-SIV is based on the paper
// “GCM-SIV: full nonce misuse-resistant authenticated encryption at under one
// cycle per byte.” by S.Gueron, and Y.Lindell,
// Proceedings of the 22nd ACM SIGSAC Conference on Computer and Communications
// Security. ACM, 2015.
// The implementation uses AES-GCM-SIV as defined in draft-irtf-cfrg-gcmsiv-08
// https://datatracker.ietf.org/doc/draft-irtf-cfrg-gcmsiv/
//
// This encryption mode is intended for authenticated encryption with
// additional authenticated data. A major security problem with AES-GCM is
// that reusing the same nonce twice leaks the authentication key.
// AES-GCM-SIV on the other hand has been designed to avoid this vulnerability.
//
// Usage bounds for the encryption mode can be found on
// https://cyber.biu.ac.il/aes-gcm-siv/
// or Section 6.3 of this paper:
// https://eprint.iacr.org/2017/702.pdf
class AesGcmSivBoringSsl : public Aead {
 public:
  static crypto::tink::util::StatusOr<std::unique_ptr<Aead>> New(
      absl::string_view key_value);

  crypto::tink::util::StatusOr<std::string> Encrypt(
      absl::string_view plaintext,
      absl::string_view additional_data) const override;

  crypto::tink::util::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext,
      absl::string_view additional_data) const override;

  ~AesGcmSivBoringSsl() override {}

 private:
  static const int IV_SIZE_IN_BYTES = 12;
  static const int TAG_SIZE_IN_BYTES = 16;

  AesGcmSivBoringSsl() {}
  crypto::tink::util::Status Init(absl::string_view key_value);

  bssl::ScopedEVP_AEAD_CTX ctx_;
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_AES_GCM_SIV_BORINGSSL_H_
