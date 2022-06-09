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

#include "tink/hybrid/internal/test_hpke_context_boringssl.h"

#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "openssl/base.h"
#include "openssl/hpke.h"
#include "tink/hybrid/internal/hpke_util.h"
#include "tink/hybrid/internal/hpke_util_boringssl.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

util::StatusOr<SenderHpkeContextBoringSsl>
TestHpkeContextBoringSsl::SetupSender(
    const HpkeParams &params, absl::string_view recipient_public_key,
    absl::string_view context_info, absl::string_view seed_for_testing) {
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
  if (!EVP_HPKE_CTX_setup_sender_with_seed_for_testing(
          context.get(), enc, &enc_len, sizeof(enc), *kem, *kdf, *aead,
          reinterpret_cast<const uint8_t *>(recipient_public_key.data()),
          recipient_public_key.size(),
          reinterpret_cast<const uint8_t *>(context_info.data()),
          context_info.size(),
          reinterpret_cast<const uint8_t *>(seed_for_testing.data()),
          seed_for_testing.size())) {
    return util::Status(absl::StatusCode::kUnknown,
                        "Unable to set up HPKE sender context.");
  }
  SenderHpkeContextBoringSsl tuple;
  tuple.context =
      absl::WrapUnique(new TestHpkeContextBoringSsl(std::move(context)));
  tuple.encapsulated_key =
      std::string(reinterpret_cast<const char *>(enc), enc_len);
  return std::move(tuple);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
