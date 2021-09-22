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

#include "tink/experimental/pqcrypto/signature/sphincs_verify_key_manager.h"

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/experimental/pqcrypto/signature/subtle/sphincs_subtle_utils.h"
#include "tink/experimental/pqcrypto/signature/subtle/sphincs_verify.h"
#include "tink/experimental/pqcrypto/signature/util/enums.h"
#include "tink/public_key_verify.h"
#include "tink/util/errors.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"

namespace crypto {
namespace tink {

using ::crypto::tink::subtle::SphincsParamsPqclean;
using ::crypto::tink::subtle::SphincsPublicKeyPqclean;
using ::crypto::tink::util::EnumsPqcrypto;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::SphincsParams;
using ::google::crypto::tink::SphincsPublicKey;

StatusOr<std::unique_ptr<PublicKeyVerify>>
SphincsVerifyKeyManager::PublicKeyVerifyFactory::Create(
    const SphincsPublicKey& public_key) const {
  SphincsParamsPqclean sphincs_params_pqclean = {
      .hash_type =
          EnumsPqcrypto::ProtoToSubtle(public_key.params().hash_type()),
      .variant = EnumsPqcrypto::ProtoToSubtle(public_key.params().variant()),
      .sig_length_type =
          EnumsPqcrypto::ProtoToSubtle(public_key.params().sig_length_type()),
      .private_key_size = public_key.params().key_size()};

  SphincsPublicKeyPqclean sphincs_public_key_pqclean(public_key.key_value(),
                                                     sphincs_params_pqclean);

  return subtle::SphincsVerify::New(sphincs_public_key_pqclean);
}

Status SphincsVerifyKeyManager::ValidateKey(const SphincsPublicKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) {
    return status;
  }

  status = subtle::ValidatePublicKeySize(key.key_value().length());
  if (!status.ok()) {
    return status;
  }

  return util::OkStatus();
}

Status SphincsVerifyKeyManager::ValidateParams(
    const SphincsParams& params) const {
  SphincsParamsPqclean sphincs_params_pqclean = {
      .hash_type = EnumsPqcrypto::ProtoToSubtle(params.hash_type()),
      .variant = EnumsPqcrypto::ProtoToSubtle(params.variant()),
      .sig_length_type = EnumsPqcrypto::ProtoToSubtle(params.sig_length_type()),
      .private_key_size = params.key_size()};

  Status status = subtle::ValidateParams(sphincs_params_pqclean);
  if (!status.ok()) {
    return status;
  }

  return util::OkStatus();
}

}  // namespace tink
}  // namespace crypto
