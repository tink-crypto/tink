// Copyright 2021 Google LLC
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

#include "tink/hybrid/internal/hpke_encrypt_boringssl.h"

#include <string>
#include <utility>

#include "absl/algorithm/container.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "openssl/base.h"
#include "openssl/err.h"
#include "openssl/hpke.h"
#include "tink/hybrid/internal/hpke_util_boringssl.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/hpke.pb.h"

namespace crypto {
namespace tink {
namespace internal {

using ::google::crypto::tink::HpkeParams;

util::StatusOr<std::unique_ptr<HpkeEncryptBoringSsl>> HpkeEncryptBoringSsl::New(
    const google::crypto::tink::HpkeParams& params,
    absl::string_view recipient_public_key, absl::string_view context_info) {
  auto hpke_encrypt = absl::WrapUnique(new HpkeEncryptBoringSsl());
  util::Status status =
      hpke_encrypt->Init(params, recipient_public_key, context_info);
  if (!status.ok()) {
    return status;
  }
  return std::move(hpke_encrypt);
}

util::StatusOr<std::unique_ptr<HpkeEncryptBoringSsl>>
HpkeEncryptBoringSsl::NewForTesting(
    const google::crypto::tink::HpkeParams& params,
    absl::string_view recipient_public_key, absl::string_view context_info,
    absl::string_view seed_for_testing) {
  auto hpke_encrypt = absl::WrapUnique(new HpkeEncryptBoringSsl());
  util::Status status = hpke_encrypt->InitForTesting(
      params, recipient_public_key, context_info, seed_for_testing);
  if (!status.ok()) {
    return status;
  }
  return std::move(hpke_encrypt);
}

util::Status HpkeEncryptBoringSsl::Init(
    const google::crypto::tink::HpkeParams& params,
    absl::string_view recipient_public_key, absl::string_view context_info) {
  util::StatusOr<const EVP_HPKE_KEM *> kem = KemParam(params);
  if (!kem.ok()) {
    return kem.status();
  }
  util::StatusOr<const EVP_HPKE_KDF *> kdf = KdfParam(params);
  if (!kdf.ok()) {
    return kdf.status();
  }
  util::StatusOr<const EVP_HPKE_AEAD *> aead = AeadParam(params);
  if (!aead.ok()) {
    return aead.status();
  }
  uint8_t enc[EVP_HPKE_MAX_ENC_LENGTH];
  size_t enc_len;
  if (!EVP_HPKE_CTX_setup_sender(
          sender_ctx_.get(), enc, &enc_len, sizeof(enc), *kem, *kdf, *aead,
          reinterpret_cast<const uint8_t *>(recipient_public_key.data()),
          recipient_public_key.size(),
          reinterpret_cast<const uint8_t *>(context_info.data()),
          context_info.size())) {
    return util::Status(absl::StatusCode::kUnknown,
                        "Unable to set up HPKE sender context.");
  }
  encapsulated_key_ = std::string(reinterpret_cast<const char *>(enc), enc_len);
  return util::OkStatus();
}

util::Status HpkeEncryptBoringSsl::InitForTesting(
    const google::crypto::tink::HpkeParams& params,
    absl::string_view recipient_public_key, absl::string_view context_info,
    absl::string_view seed_for_testing) {
  util::StatusOr<const EVP_HPKE_KEM *> kem = KemParam(params);
  if (!kem.ok()) {
    return kem.status();
  }
  util::StatusOr<const EVP_HPKE_KDF *> kdf = KdfParam(params);
  if (!kdf.ok()) {
    return kdf.status();
  }
  util::StatusOr<const EVP_HPKE_AEAD *> aead = AeadParam(params);
  if (!aead.ok()) {
    return aead.status();
  }
  uint8_t enc[EVP_HPKE_MAX_ENC_LENGTH];
  size_t enc_len;
  if (!EVP_HPKE_CTX_setup_sender_with_seed_for_testing(
          sender_ctx_.get(), enc, &enc_len, sizeof(enc), *kem, *kdf, *aead,
          reinterpret_cast<const uint8_t *>(recipient_public_key.data()),
          recipient_public_key.size(),
          reinterpret_cast<const uint8_t *>(context_info.data()),
          context_info.size(),
          reinterpret_cast<const uint8_t *>(seed_for_testing.data()),
          seed_for_testing.size())) {
    return util::Status(absl::StatusCode::kUnknown,
                        "Unable to set up HPKE sender context.");
  }
  encapsulated_key_ = std::string(reinterpret_cast<const char *>(enc), enc_len);
  return util::OkStatus();
}

util::StatusOr<std::string> HpkeEncryptBoringSsl::EncapsulateKeyThenEncrypt(
    absl::string_view plaintext, absl::string_view associated_data) {
  size_t enc_size = encapsulated_key_.size();
  std::string ciphertext(encapsulated_key_);
  subtle::ResizeStringUninitialized(
      &ciphertext, enc_size + plaintext.size() +
                       EVP_HPKE_CTX_max_overhead(sender_ctx_.get()));
  absl::c_copy(encapsulated_key_, ciphertext.begin());
  size_t max_out_len = ciphertext.size() - enc_size;
  size_t ciphertext_size;
  if (!EVP_HPKE_CTX_seal(
          sender_ctx_.get(), reinterpret_cast<uint8_t *>(&ciphertext[enc_size]),
          &ciphertext_size, max_out_len,
          reinterpret_cast<const uint8_t *>(plaintext.data()), plaintext.size(),
          reinterpret_cast<const uint8_t *>(associated_data.data()),
          associated_data.size())) {
    return util::Status(absl::StatusCode::kUnknown,
                        "BoringSSL HPKE encryption failed.");
  }
  return ciphertext;
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
