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

#include "tink/experimental/pqcrypto/signature/subtle/sphincs_verify.h"

#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/strings/str_format.h"
#include "tink/experimental/pqcrypto/signature/subtle/sphincs_helper_pqclean.h"
#include "tink/experimental/pqcrypto/signature/subtle/sphincs_subtle_utils.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// static
util::StatusOr<std::unique_ptr<PublicKeyVerify>> SphincsVerify::New(
    SphincsPublicKeyPqclean public_key) {
  auto status = internal::CheckFipsCompatibility<SphincsVerify>();
  if (!status.ok()) return status;

  util::Status key_size = ValidatePublicKeySize(public_key.GetKey().size());
  if (!key_size.ok()) {
    return key_size;
  }

  util::Status valid_parameters = ValidateParams(public_key.GetParams());
  if (!valid_parameters.ok()) {
    return valid_parameters;
  }

  return {absl::WrapUnique<SphincsVerify>(
      new SphincsVerify(std::move(public_key)))};
}

util::Status SphincsVerify::Verify(absl::string_view signature,
                                   absl::string_view data) const {
  SphincsParamsPqclean params = key_.GetParams();
  util::StatusOr<int32> key_size_index =
      SphincsKeySizeToIndex(params.private_key_size);
  if (!key_size_index.ok()) {
    return key_size_index.status();
  }

  const SphincsHelperPqclean &sphincs_helper_pqclean =
      GetSphincsHelperPqclean(params.hash_type, params.variant, *key_size_index,
                              params.sig_length_type);

  if ((sphincs_helper_pqclean.Verify(
          reinterpret_cast<const uint8_t *>(signature.data()), signature.size(),
          reinterpret_cast<const uint8_t *>(data.data()), data.size(),
          reinterpret_cast<const uint8_t *>(key_.GetKey().data()))) != 0) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Signature is not valid.");
  }

  return util::OkStatus();
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
