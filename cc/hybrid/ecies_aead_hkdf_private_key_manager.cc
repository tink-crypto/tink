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

#include "tink/hybrid/ecies_aead_hkdf_private_key_manager.h"

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/hybrid/ecies_aead_hkdf_hybrid_decrypt.h"
#include "tink/hybrid/ecies_aead_hkdf_public_key_manager.h"
#include "tink/hybrid_decrypt.h"
#include "tink/key_manager.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/ecies_aead_hkdf.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::EciesAeadHkdfKeyFormat;
using google::crypto::tink::EciesAeadHkdfPrivateKey;
using google::crypto::tink::EciesAeadHkdfPublicKey;
using google::crypto::tink::EciesHkdfKemParams;

Status EciesAeadHkdfPrivateKeyManager::ValidateKeyFormat(
    const EciesAeadHkdfKeyFormat& key_format) const {
  if (!key_format.has_params()) {
    return Status(absl::StatusCode::kInvalidArgument, "Missing params.");
  }
  return EciesAeadHkdfPublicKeyManager().ValidateParams(key_format.params());
}

StatusOr<EciesAeadHkdfPrivateKey>
EciesAeadHkdfPrivateKeyManager::CreateKey(
    const EciesAeadHkdfKeyFormat& ecies_key_format) const {
  // Generate new EC key.
  const EciesHkdfKemParams& kem_params = ecies_key_format.params().kem_params();
  auto ec_key_result = subtle::SubtleUtilBoringSSL::GetNewEcKey(
      util::Enums::ProtoToSubtle(kem_params.curve_type()));
  if (!ec_key_result.ok()) return ec_key_result.status();
  auto ec_key = ec_key_result.ValueOrDie();

  // Build EciesAeadHkdfPrivateKey.
  EciesAeadHkdfPrivateKey ecies_private_key;
  ecies_private_key.set_version(get_version());
  ecies_private_key.set_key_value(
      std::string(util::SecretDataAsStringView(ec_key.priv)));
  auto ecies_public_key = ecies_private_key.mutable_public_key();
  ecies_public_key->set_version(get_version());
  ecies_public_key->set_x(ec_key.pub_x);
  ecies_public_key->set_y(ec_key.pub_y);
  *(ecies_public_key->mutable_params()) = ecies_key_format.params();

  return ecies_private_key;
}

StatusOr<EciesAeadHkdfPublicKey>
EciesAeadHkdfPrivateKeyManager::GetPublicKey(
    const EciesAeadHkdfPrivateKey& private_key) const {
  return private_key.public_key();
}

Status EciesAeadHkdfPrivateKeyManager::ValidateKey(
    const EciesAeadHkdfPrivateKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  if (!key.has_public_key()) {
    return Status(absl::StatusCode::kInvalidArgument, "Missing public_key.");
  }
  return EciesAeadHkdfPublicKeyManager().ValidateKey(key.public_key());
}

}  // namespace tink
}  // namespace crypto
