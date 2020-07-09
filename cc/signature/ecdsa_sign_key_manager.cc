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
#include "tink/public_key_sign.h"
#include "tink/signature/ecdsa_verify_key_manager.h"
#include "tink/subtle/ecdsa_sign_boringssl.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
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
