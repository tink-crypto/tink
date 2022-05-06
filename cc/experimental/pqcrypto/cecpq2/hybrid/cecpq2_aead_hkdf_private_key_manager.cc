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

#include "tink/experimental/pqcrypto/cecpq2/hybrid/cecpq2_aead_hkdf_private_key_manager.h"

#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "openssl/hrss.h"
#include "tink/experimental/pqcrypto/cecpq2/hybrid/cecpq2_aead_hkdf_public_key_manager.h"
#include "tink/experimental/pqcrypto/cecpq2/hybrid/internal/cecpq2_aead_hkdf_hybrid_decrypt.h"
#include "tink/experimental/pqcrypto/cecpq2/subtle/cecpq2_subtle_boringssl_util.h"
#include "tink/hybrid_decrypt.h"
#include "tink/subtle/random.h"
#include "tink/subtle/subtle_util.h"
#include "tink/util/enums.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/experimental/pqcrypto/cecpq2_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::Cecpq2AeadHkdfKeyFormat;
using google::crypto::tink::Cecpq2AeadHkdfPrivateKey;
using google::crypto::tink::Cecpq2AeadHkdfPublicKey;

Status Cecpq2AeadHkdfPrivateKeyManager::ValidateKeyFormat(
    const Cecpq2AeadHkdfKeyFormat& key_format) const {
  if (!key_format.has_params()) {
    return Status(absl::StatusCode::kInvalidArgument, "Missing params.");
  }
  return Cecpq2AeadHkdfPublicKeyManager().ValidateParams(key_format.params());
}

StatusOr<Cecpq2AeadHkdfPrivateKey> Cecpq2AeadHkdfPrivateKeyManager::CreateKey(
    const Cecpq2AeadHkdfKeyFormat& cecpq2_key_format) const {
  // Generate CECPQ2 key pair
  auto cecpq2_key_pair_or =
      pqc::GenerateCecpq2Keypair(subtle::EllipticCurveType::CURVE25519);
  if (!cecpq2_key_pair_or.ok()) return cecpq2_key_pair_or.status();
  auto cecpq2_key_pair = std::move(cecpq2_key_pair_or.value());

  // Build Cecpq2AeadHkdfPrivateKey
  Cecpq2AeadHkdfPrivateKey cecpq2_private_key;
  cecpq2_private_key.set_version(get_version());
  cecpq2_private_key.set_x25519_private_key(std::string(
      util::SecretDataAsStringView(cecpq2_key_pair.x25519_key_pair.priv)));
  cecpq2_private_key.set_hrss_private_key_seed(
      std::string(util::SecretDataAsStringView(
          cecpq2_key_pair.hrss_key_pair.hrss_private_key_seed)));

  auto cecpq2_public_key = cecpq2_private_key.mutable_public_key();
  cecpq2_public_key->set_version(get_version());
  cecpq2_public_key->set_x25519_public_key_x(
      cecpq2_key_pair.x25519_key_pair.pub_x);
  cecpq2_public_key->set_x25519_public_key_y(
      cecpq2_key_pair.x25519_key_pair.pub_y);
  cecpq2_public_key->set_hrss_public_key_marshalled(
      cecpq2_key_pair.hrss_key_pair.hrss_public_key_marshaled);
  *(cecpq2_public_key->mutable_params()) = cecpq2_key_format.params();

  return cecpq2_private_key;
}

StatusOr<Cecpq2AeadHkdfPublicKey> Cecpq2AeadHkdfPrivateKeyManager::GetPublicKey(
    const Cecpq2AeadHkdfPrivateKey& private_key) const {
  return private_key.public_key();
}

Status Cecpq2AeadHkdfPrivateKeyManager::ValidateKey(
    const Cecpq2AeadHkdfPrivateKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  if (!key.has_public_key()) {
    return Status(absl::StatusCode::kInvalidArgument, "Missing public_key.");
  }
  return Cecpq2AeadHkdfPublicKeyManager().ValidateKey(key.public_key());
}

}  // namespace tink
}  // namespace crypto
