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

#include "tink/experimental/pqcrypto/signature/falcon_verify_key_manager.h"

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/experimental/pqcrypto/signature/subtle/falcon_subtle_utils.h"
#include "tink/experimental/pqcrypto/signature/subtle/falcon_verify.h"
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

using ::crypto::tink::subtle::FalconPublicKeyPqclean;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::FalconPublicKey;

StatusOr<std::unique_ptr<PublicKeyVerify>>
FalconVerifyKeyManager::PublicKeyVerifyFactory::Create(
    const FalconPublicKey& public_key) const {
  StatusOr<FalconPublicKeyPqclean> falcon_public_key_pqclean =
      FalconPublicKeyPqclean::NewPublicKey(public_key.key_value());

  if (!falcon_public_key_pqclean.ok()) {
    return falcon_public_key_pqclean.status();
  }

  return subtle::FalconVerify::New(*falcon_public_key_pqclean);
}

Status FalconVerifyKeyManager::ValidateKey(const FalconPublicKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) {
    return status;
  }

  status = subtle::ValidateFalconPublicKeySize(key.key_value().length());
  if (!status.ok()) {
    return status;
  }

  return Status::OK;
}

}  // namespace tink
}  // namespace crypto
