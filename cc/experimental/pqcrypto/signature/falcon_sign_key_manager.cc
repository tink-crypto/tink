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

#include "tink/experimental/pqcrypto/signature/falcon_sign_key_manager.h"

#include <memory>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/experimental/pqcrypto/signature/falcon_verify_key_manager.h"
#include "tink/experimental/pqcrypto/signature/subtle/falcon_sign.h"
#include "tink/experimental/pqcrypto/signature/subtle/falcon_subtle_utils.h"
#include "tink/public_key_sign.h"
#include "tink/util/errors.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"

namespace crypto {
namespace tink {

using ::crypto::tink::subtle::FalconKeyPair;
using ::crypto::tink::subtle::FalconPrivateKeyPqclean;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::FalconKeyFormat;
using ::google::crypto::tink::FalconPrivateKey;
using ::google::crypto::tink::FalconPublicKey;

StatusOr<FalconPrivateKey> FalconSignKeyManager::CreateKey(
    const FalconKeyFormat& key_format) const {
  util::StatusOr<FalconKeyPair> key_pair =
      subtle::GenerateFalconKeyPair(key_format.key_size());

  if (!key_pair.status().ok()) {
    return key_pair.status();
  }

  FalconPrivateKey falcon_private_key;
  falcon_private_key.set_version(get_version());
  falcon_private_key.set_key_value(
      util::SecretDataAsStringView(key_pair->GetPrivateKey().GetKey()));

  FalconPublicKey* falcon_public_key = falcon_private_key.mutable_public_key();
  falcon_public_key->set_version(get_version());
  falcon_public_key->set_key_value(key_pair->GetPublicKey().GetKey());

  return falcon_private_key;
}

StatusOr<std::unique_ptr<PublicKeySign>>
FalconSignKeyManager::PublicKeySignFactory::Create(
    const FalconPrivateKey& private_key) const {
  util::SecretData sk_data =
      util::SecretDataFromStringView(private_key.key_value());

  util::StatusOr<FalconPrivateKeyPqclean> falcon_private_key =
      FalconPrivateKeyPqclean::NewPrivateKey(sk_data);

  if (!falcon_private_key.ok()) {
    return falcon_private_key.status();
  }

  return subtle::FalconSign::New(*falcon_private_key);
}

Status FalconSignKeyManager::ValidateKey(const FalconPrivateKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) {
    return status;
  }

  status = subtle::ValidateFalconPrivateKeySize(key.key_value().length());
  if (!status.ok()) {
    return status;
  }

  return FalconVerifyKeyManager().ValidateKey(key.public_key());
}

Status FalconSignKeyManager::ValidateKeyFormat(
    const FalconKeyFormat& key_format) const {
  Status status = subtle::ValidateFalconPrivateKeySize(key_format.key_size());
  if (!status.ok()) {
    return status;
  }

  return util::OkStatus();
}

}  // namespace tink
}  // namespace crypto
