// Copyright 2022 Google LLC
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

#include "tink/hybrid/internal/hpke_context_boringssl.h"

#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "openssl/base.h"
#include "openssl/hpke.h"
#include "tink/hybrid/internal/hpke_util.h"
#include "tink/hybrid/internal/hpke_util_boringssl.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

util::StatusOr<SenderHpkeContextBoringSsl>
HpkeContextBoringSsl::SetupSender(const HpkeParams& params,
                                  absl::string_view recipient_public_key,
                                  absl::string_view context_info) {
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
  SslUniquePtr<EVP_HPKE_CTX> context(EVP_HPKE_CTX_new());
  if (!EVP_HPKE_CTX_setup_sender(
          context.get(), enc, &enc_len, sizeof(enc), *kem, *kdf, *aead,
          reinterpret_cast<const uint8_t *>(recipient_public_key.data()),
          recipient_public_key.size(),
          reinterpret_cast<const uint8_t *>(context_info.data()),
          context_info.size())) {
    return util::Status(absl::StatusCode::kUnknown,
                        "Unable to set up HPKE sender context.");
  }
  SenderHpkeContextBoringSsl tuple;
  tuple.context =
      absl::WrapUnique(new HpkeContextBoringSsl(std::move(context)));
  tuple.encapsulated_key =
      std::string(reinterpret_cast<const char *>(enc), enc_len);
  return std::move(tuple);
}

util::StatusOr<std::unique_ptr<HpkeContextBoringSsl>>
HpkeContextBoringSsl::SetupRecipient(
    const HpkeParams& params, const util::SecretData& recipient_private_key,
    absl::string_view encapsulated_key, absl::string_view info) {
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
  bssl::ScopedEVP_HPKE_KEY hpke_key;
  if (!EVP_HPKE_KEY_init(
          hpke_key.get(), *kem,
          reinterpret_cast<const uint8_t *>(recipient_private_key.data()),
          recipient_private_key.size())) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Unable to initialize BoringSSL HPKE recipient private key.");
  }
  SslUniquePtr<EVP_HPKE_CTX> context(EVP_HPKE_CTX_new());
  if (!EVP_HPKE_CTX_setup_recipient(
          context.get(), hpke_key.get(), *kdf, *aead,
          reinterpret_cast<const uint8_t *>(encapsulated_key.data()),
          encapsulated_key.size(),
          reinterpret_cast<const uint8_t *>(info.data()), info.size())) {
    return util::Status(absl::StatusCode::kUnknown,
                        "Unable to set up BoringSSL HPKE recipient context.");
  }
  return absl::WrapUnique(new HpkeContextBoringSsl(std::move(context)));
}

util::StatusOr<std::string> HpkeContextBoringSsl::Seal(
    absl::string_view plaintext, absl::string_view associated_data) {
  std::string ciphertext;
  subtle::ResizeStringUninitialized(
      &ciphertext,
      plaintext.size() + EVP_HPKE_CTX_max_overhead(context_.get()));
  size_t max_out_len = ciphertext.size();
  size_t ciphertext_size;
  if (!EVP_HPKE_CTX_seal(
          context_.get(), reinterpret_cast<uint8_t *>(&ciphertext[0]),
          &ciphertext_size, max_out_len,
          reinterpret_cast<const uint8_t *>(plaintext.data()), plaintext.size(),
          reinterpret_cast<const uint8_t *>(associated_data.data()),
          associated_data.size())) {
    return util::Status(absl::StatusCode::kUnknown,
                        "BoringSSL HPKE encryption failed.");
  }
  if (ciphertext_size < ciphertext.size()) {
    subtle::ResizeStringUninitialized(&ciphertext, ciphertext_size);
  }
  return ciphertext;
}

util::StatusOr<std::string> HpkeContextBoringSsl::Open(
    absl::string_view ciphertext, absl::string_view associated_data) {
  std::string plaintext;
  subtle::ResizeStringUninitialized(&plaintext, ciphertext.size());
  size_t plaintext_size;
  if (!EVP_HPKE_CTX_open(
          context_.get(), reinterpret_cast<uint8_t *>(&plaintext[0]),
          &plaintext_size, plaintext.size(),
          reinterpret_cast<const uint8_t *>(ciphertext.data()),
          ciphertext.size(),
          reinterpret_cast<const uint8_t *>(associated_data.data()),
          associated_data.size())) {
    return util::Status(absl::StatusCode::kUnknown,
                        "BoringSSL HPKE decryption failed.");
  }
  subtle::ResizeStringUninitialized(&plaintext, plaintext_size);
  return plaintext;
}

util::StatusOr<util::SecretData> HpkeContextBoringSsl::Export(
    absl::string_view exporter_context, int64_t secret_length) {
  std::string secret;
  subtle::ResizeStringUninitialized(&secret, secret_length);
  if (!EVP_HPKE_CTX_export(
          context_.get(), reinterpret_cast<uint8_t *>(&secret[0]),
          secret_length,
          reinterpret_cast<const uint8_t *>(exporter_context.data()),
          exporter_context.size())) {
    return util::Status(absl::StatusCode::kUnknown, "Unable to export secret.");
  }
  return util::SecretDataFromStringView(secret);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
