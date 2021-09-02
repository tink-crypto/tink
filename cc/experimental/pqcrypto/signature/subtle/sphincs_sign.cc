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

#include "tink/experimental/pqcrypto/signature/subtle/sphincs_sign.h"

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
util::StatusOr<std::unique_ptr<PublicKeySign>> SphincsSign::New(
    SphincsPrivateKeyPqclean key) {
  auto status = internal::CheckFipsCompatibility<SphincsSign>();
  if (!status.ok()) return status;

  util::Status key_size = ValidatePrivateKeySize(key.GetKey().size());
  if (!key_size.ok()) {
    return key_size;
  }

  return {absl::WrapUnique(new SphincsSign(std::move(key)))};
}

util::StatusOr<std::string> SphincsSign::Sign(absl::string_view data) const {
  util::StatusOr<int32> key_size_index =
      SphincsKeySizeToIndex(key_.GetKey().size());
  if (!key_size_index.ok()) {
    return key_size_index.status();
  }

  size_t sig_length;
  SphincsParamsPqclean params = key_.GetParams();
  const SphincsHelperPqclean &sphincs_helper_pqclean =
      GetSphincsHelperPqclean(params.hash_type, params.variant, *key_size_index,
                              params.sig_length_type);
  std::string signature(sphincs_helper_pqclean.GetSignatureLength(), '0');

  if ((sphincs_helper_pqclean.Sign(
           reinterpret_cast<uint8_t *>(signature.data()), &sig_length,
           reinterpret_cast<const uint8_t *>(data.data()), data.size(),
           reinterpret_cast<const uint8_t *>(key_.GetKey().data())) != 0)) {
    return util::Status(util::error::INTERNAL, "Signing failed.");
  }

  return signature;
}

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
