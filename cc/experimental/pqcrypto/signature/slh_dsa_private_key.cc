// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/experimental/pqcrypto/signature/slh_dsa_private_key.h"

#include <cstdint>
#include <string>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "openssl/boringssl/src/include/openssl/mem.h"
#define OPENSSL_UNSTABLE_EXPERIMENTAL_SPX
#include "openssl/experimental/spx.h"
#undef OPENSSL_UNSTABLE_EXPERIMENTAL_SPX
#include "tink/experimental/pqcrypto/signature/slh_dsa_public_key.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/key.h"
#include "tink/partial_key_access_token.h"
#include "tink/restricted_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

util::StatusOr<SlhDsaPrivateKey> SlhDsaPrivateKey::Create(
    const SlhDsaPublicKey& public_key, const RestrictedData& private_key_bytes,
    PartialKeyAccessToken token) {
  // Only 64-byte private keys are currently supported.
  if (private_key_bytes.size() != SPX_SECRET_KEY_BYTES) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "SLH-DSA private key length must be 64 bytes.");
  }

  if (public_key.GetParameters().GetPrivateKeySizeInBytes() !=
      private_key_bytes.size()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Private key size does not match parameters");
  }
  // Confirm that the private key and public key are a valid SLH-DSA key pair.
  std::string public_key_bytes_regen;
  public_key_bytes_regen.resize(SPX_PUBLIC_KEY_BYTES);
  std::string private_key_bytes_regen;
  private_key_bytes_regen.resize(SPX_SECRET_KEY_BYTES);

  absl::string_view expected_private_key_bytes =
      private_key_bytes.GetSecret(InsecureSecretKeyAccess::Get());
  SPX_generate_key_from_seed(
      reinterpret_cast<uint8_t*>(public_key_bytes_regen.data()),
      reinterpret_cast<uint8_t*>(private_key_bytes_regen.data()),
      // Uses the first 48 bytes of the private key as seed.
      reinterpret_cast<const uint8_t*>(expected_private_key_bytes.data()));

  absl::string_view expected_public_key_bytes =
      public_key.GetPublicKeyBytes(token);

  if (CRYPTO_memcmp(expected_public_key_bytes.data(),
                    public_key_bytes_regen.data(), SPX_PUBLIC_KEY_BYTES) != 0 ||
      CRYPTO_memcmp(expected_private_key_bytes.data(),
                    private_key_bytes_regen.data(),
                    SPX_SECRET_KEY_BYTES) != 0) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Invalid SLH-DSA key pair");
  }

  return SlhDsaPrivateKey(public_key, private_key_bytes);
}

bool SlhDsaPrivateKey::operator==(const Key& other) const {
  const SlhDsaPrivateKey* that = dynamic_cast<const SlhDsaPrivateKey*>(&other);
  if (that == nullptr) {
    return false;
  }
  return public_key_ == that->public_key_ &&
         private_key_bytes_ == that->private_key_bytes_;
}

}  // namespace tink
}  // namespace crypto
