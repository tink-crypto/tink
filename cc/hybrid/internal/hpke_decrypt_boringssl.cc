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

#include "tink/hybrid/internal/hpke_decrypt_boringssl.h"

#include <string>
#include <utility>

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

util::StatusOr<std::unique_ptr<HpkeDecryptBoringSsl>> HpkeDecryptBoringSsl::New(
    const google::crypto::tink::HpkeParams& params,
    const HpkeKeyBoringSsl& hpke_key, absl::string_view encapsulated_key,
    absl::string_view context_info) {
  auto hpke_decrypt = absl::WrapUnique(new HpkeDecryptBoringSsl());
  util::Status status =
      hpke_decrypt->Init(params, hpke_key, encapsulated_key, context_info);
  if (!status.ok()) {
    return status;
  }
  return std::move(hpke_decrypt);
}

util::Status HpkeDecryptBoringSsl::Init(const HpkeParams& params,
                                        const HpkeKeyBoringSsl& hpke_key,
                                        absl::string_view encapsulated_key,
                                        absl::string_view context_info) {
  util::StatusOr<const EVP_HPKE_KEM *> kem = KemParam(params);
  if (!kem.ok()) {
    return kem.status();
  }
  if (params.kem() != hpke_key.kem()) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("Specified KEM parameter '", params.kem(),
                     "' does not match given HPKE key's KEM parameter '",
                     hpke_key.kem(), "'."));
  }
  util::StatusOr<const EVP_HPKE_KDF *> kdf = KdfParam(params);
  if (!kdf.ok()) {
    return kdf.status();
  }
  util::StatusOr<const EVP_HPKE_AEAD *> aead = AeadParam(params);
  if (!aead.ok()) {
    return aead.status();
  }
  if (!EVP_HPKE_CTX_setup_recipient(
          recipient_ctx_.get(), hpke_key.recipient_private_key(), *kdf, *aead,
          reinterpret_cast<const uint8_t *>(encapsulated_key.data()),
          encapsulated_key.size(),
          reinterpret_cast<const uint8_t *>(context_info.data()),
          context_info.size())) {
    return util::Status(absl::StatusCode::kUnknown,
                        "Unable to set up BoringSSL HPKE recipient context.");
  }
  return util::OkStatus();
}

util::StatusOr<std::string> HpkeDecryptBoringSsl::Decrypt(
    absl::string_view ciphertext, absl::string_view associated_data) {
  std::string plaintext;
  subtle::ResizeStringUninitialized(&plaintext, ciphertext.size());
  size_t plaintext_size;
  if (!EVP_HPKE_CTX_open(
          recipient_ctx_.get(), reinterpret_cast<uint8_t *>(&plaintext[0]),
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

}  // namespace internal
}  // namespace tink
}  // namespace crypto
