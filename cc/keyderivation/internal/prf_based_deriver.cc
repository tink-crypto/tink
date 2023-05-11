// Copyright 2019 Google LLC
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

#include "tink/keyderivation/internal/prf_based_deriver.h"

#include <memory>
#include <utility>

#include "tink/cleartext_keyset_handle.h"
#include "tink/keyset_handle.h"
#include "tink/registry.h"
#include "tink/subtle/prf/streaming_prf.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;

util::StatusOr<std::unique_ptr<KeysetDeriver>> PrfBasedDeriver::New(
    const KeyData& prf_key, const KeyTemplate& key_template) {
  // Validate `prf_key`.
  util::StatusOr<std::unique_ptr<StreamingPrf>> streaming_prf =
      Registry::GetPrimitive<StreamingPrf>(prf_key);
  if (!streaming_prf.ok()) {
    return streaming_prf.status();
  }

  // Validate `key_template`.
  std::unique_ptr<InputStream> randomness = (*streaming_prf)->ComputePrf("s");
  util::StatusOr<KeyData> key_data =
      internal::RegistryImpl::GlobalInstance().DeriveKey(key_template,
                                                         randomness.get());
  if (!key_data.ok()) {
    return key_data.status();
  }

  return {absl::WrapUnique<PrfBasedDeriver>(
      new PrfBasedDeriver(*std::move(streaming_prf), key_template))};
}

util::StatusOr<std::unique_ptr<KeysetHandle>> PrfBasedDeriver::DeriveKeyset(
    absl::string_view salt) const {
  std::unique_ptr<InputStream> randomness = streaming_prf_->ComputePrf(salt);

  util::StatusOr<KeyData> key_data =
      crypto::tink::internal::RegistryImpl::GlobalInstance().DeriveKey(
          key_template_, randomness.get());
  if (!key_data.ok()) {
    return key_data.status();
  }

  // Fill in placeholder values for key ID, status, and output prefix type.
  // These will be populated with the correct values in the keyset deriver
  // factory. This is acceptable because the keyset as-is will never leave Tink,
  // and the user only interacts via the keyset deriver factory.
  Keyset::Key key;
  *key.mutable_key_data() = *key_data;
  key.set_status(KeyStatusType::UNKNOWN_STATUS);
  key.set_key_id(0);
  key.set_output_prefix_type(OutputPrefixType::UNKNOWN_PREFIX);

  Keyset keyset;
  *keyset.add_key() = key;
  keyset.set_primary_key_id(0);

  return CleartextKeysetHandle::GetKeysetHandle(keyset);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
