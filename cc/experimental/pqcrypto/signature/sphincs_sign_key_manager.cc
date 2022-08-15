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

#include "tink/experimental/pqcrypto/signature/sphincs_sign_key_manager.h"

#include <memory>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/experimental/pqcrypto/signature/sphincs_verify_key_manager.h"
#include "tink/experimental/pqcrypto/signature/subtle/sphincs_sign.h"
#include "tink/experimental/pqcrypto/signature/subtle/sphincs_subtle_utils.h"
#include "tink/experimental/pqcrypto/signature/util/enums.h"
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

using ::crypto::tink::subtle::SphincsKeyPair;
using ::crypto::tink::subtle::SphincsParamsPqclean;
using ::crypto::tink::subtle::SphincsPrivateKeyPqclean;
using ::crypto::tink::util::EnumsPqcrypto;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::SphincsKeyFormat;
using ::google::crypto::tink::SphincsPrivateKey;
using ::google::crypto::tink::SphincsPublicKey;

StatusOr<SphincsPrivateKey> SphincsSignKeyManager::CreateKey(
    const SphincsKeyFormat& key_format) const {
  SphincsParamsPqclean sphincs_params_pqclean = {
      .hash_type =
          EnumsPqcrypto::ProtoToSubtle(key_format.params().hash_type()),
      .variant = EnumsPqcrypto::ProtoToSubtle(key_format.params().variant()),
      .sig_length_type =
          EnumsPqcrypto::ProtoToSubtle(key_format.params().sig_length_type()),
      .private_key_size = key_format.params().key_size()};

  util::StatusOr<SphincsKeyPair> key_pair =
      GenerateSphincsKeyPair(sphincs_params_pqclean);

  if (!key_pair.status().ok()) {
    return key_pair.status();
  }

  SphincsPrivateKey sphincs_private_key;
  sphincs_private_key.set_version(get_version());
  sphincs_private_key.set_key_value(
      util::SecretDataAsStringView(key_pair->GetPrivateKey().GetKey()));

  SphincsPublicKey* sphincs_public_key =
      sphincs_private_key.mutable_public_key();
  sphincs_public_key->set_version(get_version());
  sphincs_public_key->set_key_value(key_pair->GetPublicKey().GetKey());
  *(sphincs_public_key->mutable_params()) = key_format.params();

  return sphincs_private_key;
}

StatusOr<std::unique_ptr<PublicKeySign>>
SphincsSignKeyManager::PublicKeySignFactory::Create(
    const SphincsPrivateKey& private_key) const {
  util::SecretData sk_data =
      util::SecretDataFromStringView(private_key.key_value());
  SphincsParamsPqclean sphincs_params_pqclean = {
      .hash_type = EnumsPqcrypto::ProtoToSubtle(
          private_key.public_key().params().hash_type()),
      .variant = EnumsPqcrypto::ProtoToSubtle(
          private_key.public_key().params().variant()),
      .sig_length_type = EnumsPqcrypto::ProtoToSubtle(
          private_key.public_key().params().sig_length_type()),
      .private_key_size = private_key.public_key().params().key_size()};

  SphincsPrivateKeyPqclean sphincs_private_key_pqclean(sk_data,
                                                       sphincs_params_pqclean);

  return subtle::SphincsSign::New(sphincs_private_key_pqclean);
}

Status SphincsSignKeyManager::ValidateKey(const SphincsPrivateKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) {
    return status;
  }

  status = subtle::ValidatePrivateKeySize(key.key_value().length());
  if (!status.ok()) {
    return status;
  }

  return SphincsVerifyKeyManager().ValidateKey(key.public_key());
}

Status SphincsSignKeyManager::ValidateKeyFormat(
    const SphincsKeyFormat& key_format) const {
  if (!key_format.has_params()) {
    return Status(absl::StatusCode::kInvalidArgument, "Missing params.");
  }

  return SphincsVerifyKeyManager().ValidateParams(key_format.params());
}

}  // namespace tink
}  // namespace crypto
