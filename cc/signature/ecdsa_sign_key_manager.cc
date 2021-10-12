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

#include "tink/signature/ecdsa_sign_key_manager.h"

#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "tink/config/tink_fips.h"
#include "tink/public_key_sign.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/subtle/ecdsa_sign_boringssl.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/ecdsa.pb.h"

namespace crypto {
namespace tink {

using crypto::tink::util::Enums;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::EcdsaKeyFormat;
using google::crypto::tink::EcdsaPrivateKey;
using google::crypto::tink::EcdsaPublicKey;

StatusOr<EcdsaPrivateKey> EcdsaSignKeyManager::CreateKey(
    const EcdsaKeyFormat& ecdsa_key_format) const {
  // Generate new EC key.
  auto ec_key_result = subtle::SubtleUtilBoringSSL::GetNewEcKey(
      util::Enums::ProtoToSubtle(ecdsa_key_format.params().curve()));
  if (!ec_key_result.ok()) return ec_key_result.status();
  auto ec_key = ec_key_result.ValueOrDie();

  // Build EcdsaPrivateKey.
  EcdsaPrivateKey ecdsa_private_key;
  ecdsa_private_key.set_version(get_version());
  ecdsa_private_key.set_key_value(
      std::string(util::SecretDataAsStringView(ec_key.priv)));
  auto ecdsa_public_key = ecdsa_private_key.mutable_public_key();
  ecdsa_public_key->set_version(get_version());
  ecdsa_public_key->set_x(ec_key.pub_x);
  ecdsa_public_key->set_y(ec_key.pub_y);
  *(ecdsa_public_key->mutable_params()) = ecdsa_key_format.params();
  return ecdsa_private_key;
}

StatusOr<EcdsaPrivateKey> EcdsaSignKeyManager::DeriveKey(
    const EcdsaKeyFormat& ecdsa_key_format, InputStream* input_stream) const {
  if (IsFipsModeEnabled()) {
    return crypto::tink::util::Status(
        absl::StatusCode::kInternal,
        "Deriving EC keys is not allowed in FIPS mode.");
  }

  // Extract enough random bytes from the input_stream to match the security
  // level of the EC. Note that the input_stream here must come from a PRF
  // and will not use more bytes than required by the security level of the EC.
  // Providing an input_stream which has more bytes available than required,
  // will result in the same keys being generated.
  int random_bytes_used = 0;
  switch (ecdsa_key_format.params().curve()) {
    case google::crypto::tink::EllipticCurveType::NIST_P256:
      random_bytes_used = 16;
      break;
    case google::crypto::tink::EllipticCurveType::NIST_P384:
      random_bytes_used = 24;
      break;
    case google::crypto::tink::EllipticCurveType::NIST_P521:
      random_bytes_used = 32;
      break;
    default:
      return crypto::tink::util::Status(
          crypto::tink::util::error::INVALID_ARGUMENT,
          "Curve does not support key derivation.");
  }

  crypto::tink::util::StatusOr<util::SecretData> randomness =
      ReadSecretBytesFromStream(random_bytes_used, input_stream);
  if (!randomness.ok()) {
    if (randomness.status().code() == absl::StatusCode::kOutOfRange) {
      return crypto::tink::util::Status(
          crypto::tink::util::error::INVALID_ARGUMENT,
          "Could not get enough pseudorandomness from input stream");
    }
    return randomness.status();
  }

  // Generate new EC key from the seed.
  crypto::tink::util::StatusOr<subtle::SubtleUtilBoringSSL::EcKey> ec_key =
      subtle::SubtleUtilBoringSSL::GetNewEcKeyFromSeed(
          util::Enums::ProtoToSubtle(ecdsa_key_format.params().curve()),
          *randomness);

  if (!ec_key.ok()) {
    return ec_key.status();
  }

  // Build EcdsaPrivateKey.
  EcdsaPrivateKey ecdsa_private_key;
  ecdsa_private_key.set_version(get_version());
  ecdsa_private_key.set_key_value(
      std::string(util::SecretDataAsStringView(ec_key->priv)));
  EcdsaPublicKey* ecdsa_public_key = ecdsa_private_key.mutable_public_key();
  ecdsa_public_key->set_version(get_version());
  ecdsa_public_key->set_x(ec_key->pub_x);
  ecdsa_public_key->set_y(ec_key->pub_y);
  *(ecdsa_public_key->mutable_params()) = ecdsa_key_format.params();
  return ecdsa_private_key;
}

StatusOr<std::unique_ptr<PublicKeySign>>
EcdsaSignKeyManager::PublicKeySignFactory::Create(
    const EcdsaPrivateKey& ecdsa_private_key) const {
  const EcdsaPublicKey& public_key = ecdsa_private_key.public_key();
  subtle::SubtleUtilBoringSSL::EcKey ec_key;
  ec_key.curve = Enums::ProtoToSubtle(public_key.params().curve());
  ec_key.pub_x = public_key.x();
  ec_key.pub_y = public_key.y();
  ec_key.priv = util::SecretDataFromStringView(ecdsa_private_key.key_value());
  auto result = subtle::EcdsaSignBoringSsl::New(
      ec_key, Enums::ProtoToSubtle(public_key.params().hash_type()),
      Enums::ProtoToSubtle(public_key.params().encoding()));
  if (!result.ok()) return result.status();
  return {std::move(result.ValueOrDie())};
}

Status EcdsaSignKeyManager::ValidateKey(const EcdsaPrivateKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  return EcdsaVerifyKeyManager().ValidateKey(key.public_key());
}

Status EcdsaSignKeyManager::ValidateKeyFormat(
    const EcdsaKeyFormat& key_format) const {
  if (!key_format.has_params()) {
    return Status(util::error::INVALID_ARGUMENT, "Missing params.");
  }
  return EcdsaVerifyKeyManager().ValidateParams(key_format.params());
}

}  // namespace tink
}  // namespace crypto
