// Copyright 2024 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

#include "tink/keyderivation/internal/key_derivers.h"

#include <memory>
#include <string>
#include <typeindex>
#include <utility>

#include "absl/container/flat_hash_map.h"
#include "absl/functional/any_invocable.h"
#include "absl/log/check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_gcm_key.h"
#include "tink/aead/aes_gcm_parameters.h"
#include "tink/aead/aes_gcm_proto_serialization.h"
#include "tink/input_stream.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/partial_key_access.h"
#include "tink/restricted_data.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

using KeyDeriverFn = absl::AnyInvocable<util::StatusOr<std::unique_ptr<Key>>(
    const Parameters&, InputStream*) const>;
using KeyDeriverFnMap = absl::flat_hash_map<std::type_index, KeyDeriverFn>;

util::StatusOr<std::unique_ptr<AesGcmKey>> DeriveAesGcmKey(
    const Parameters& generic_params, InputStream* randomness) {
  const AesGcmParameters* params =
      dynamic_cast<const AesGcmParameters*>(&generic_params);
  if (params == nullptr) {
    return util::Status(absl::StatusCode::kInternal,
                        "Parameters is not AesGcmParameters.");
  }
  util::StatusOr<std::string> randomness_str =
      ReadBytesFromStream(params->KeySizeInBytes(), randomness);
  if (!randomness_str.ok()) {
    return randomness_str.status();
  }
  util::StatusOr<AesGcmKey> key = AesGcmKey::Create(
      *params, RestrictedData(*randomness_str, InsecureSecretKeyAccess::Get()),
      /*id_requirement=*/absl::nullopt, GetPartialKeyAccess());
  if (!key.ok()) {
    return key.status();
  }
  return absl::make_unique<AesGcmKey>(*key);
}

const KeyDeriverFnMap& ParametersToKeyDeriver() {
  static const KeyDeriverFnMap* instance = [] {
    CHECK_OK(RegisterAesGcmProtoSerialization());

    static KeyDeriverFnMap* m = new KeyDeriverFnMap();
    m->insert({std::type_index(typeid(AesGcmParameters)), DeriveAesGcmKey});
    return m;
  }();
  return *instance;
}

util::StatusOr<std::unique_ptr<Key>> DeriveKey(const Parameters& params,
                                               InputStream* randomness) {
  auto it = ParametersToKeyDeriver().find(std::type_index(typeid(params)));
  if (it == ParametersToKeyDeriver().end()) {
    return util::Status(
        absl::StatusCode::kUnimplemented,
        absl::StrCat("Key deriver not found for ", typeid(params).name()));
  }
  return it->second(params, randomness);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
