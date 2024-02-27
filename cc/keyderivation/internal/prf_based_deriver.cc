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

#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "tink/aead/aes_gcm_proto_serialization.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/input_stream.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/registry_impl.h"
#include "tink/key.h"
#include "tink/key_status.h"
#include "tink/keyderivation/internal/config_prf_for_deriver.h"
#include "tink/keyderivation/internal/key_derivers.h"
#include "tink/keyderivation/keyset_deriver.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_handle_builder.h"
#include "tink/parameters.h"
#include "tink/subtle/prf/streaming_prf.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;

util::StatusOr<std::unique_ptr<KeysetHandle>> DeriveWithGlobalRegistry(
    const KeyTemplate& key_template, InputStream& randomness) {
  util::StatusOr<KeyData> key_data =
      RegistryImpl::GlobalInstance().DeriveKey(key_template, &randomness);
  if (!key_data.ok()) {
    return key_data.status();
  }

  // Fill placeholders key ID 0, OutputPrefixType::UNKNOWN_PREFIX, and
  // KeyStatusType::UNKNOWN_STATUS.
  // Tink users interact with this keyset only after it has been processed by
  // KeysetDeriverSetWrapper::DeriveKeyset, which uses
  // google::crypto::tink::KeyData's value field (the serialized *Key proto) and
  // nothing else.
  // http://google3/third_party/tink/cc/keyderivation/keyset_deriver_wrapper.cc;l=88-91;rcl=592310815
  Keyset::Key key;
  *key.mutable_key_data() = *key_data;
  key.set_key_id(0);
  key.set_output_prefix_type(OutputPrefixType::UNKNOWN_PREFIX);
  key.set_status(KeyStatusType::UNKNOWN_STATUS);
  Keyset keyset;
  *keyset.add_key() = key;
  keyset.set_primary_key_id(0);

  return CleartextKeysetHandle::GetKeysetHandle(keyset);
}

util::StatusOr<std::unique_ptr<KeysetHandle>> DeriveWithHardCodedMap(
    const KeyTemplate& key_template, InputStream& randomness) {
  // Fill placeholders OutputPrefixType::RAW and KeyStatus::kEnabled.
  // Tink users interact with this keyset only after it has been processed by
  // KeysetDeriverSetWrapper::DeriveKeyset, which uses
  // google::crypto::tink::KeyData's value field (the serialized *Key proto) and
  // nothing else.
  // http://google3/third_party/tink/cc/keyderivation/keyset_deriver_wrapper.cc;l=88-91;rcl=592310815
  util::StatusOr<ProtoParametersSerialization> serialization =
      ProtoParametersSerialization::Create(
          key_template.type_url(), OutputPrefixType::RAW, key_template.value());
  if (!serialization.ok()) {
    return serialization.status();
  }
  util::StatusOr<std::unique_ptr<Parameters>> params =
      MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  if (!params.ok()) {
    return params.status();
  }

  util::StatusOr<std::unique_ptr<Key>> key =
      DeriveKey(**std::move(params), &randomness);
  if (!key.ok()) {
    return key.status();
  }

  KeysetHandleBuilder::Entry entry = KeysetHandleBuilder::Entry::CreateFromKey(
      *std::move(key), KeyStatus::kEnabled, /*is_primary=*/true);
  util::StatusOr<KeysetHandle> handle =
      KeysetHandleBuilder().AddEntry(std::move(entry)).Build();
  if (!handle.ok()) {
    return handle.status();
  }
  return absl::make_unique<KeysetHandle>(*handle);
}

util::StatusOr<std::unique_ptr<KeysetHandle>> DeriveKeysetHandle(
    const KeyTemplate& key_template, InputStream& randomness) {
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      DeriveWithGlobalRegistry(key_template, randomness);
  if (!handle.ok()) {
    return DeriveWithHardCodedMap(key_template, randomness);
  }
  return *std::move(handle);
}

util::Status RegisterProtoSerializations() {
  return RegisterAesGcmProtoSerialization();
}

util::StatusOr<std::unique_ptr<StreamingPrf>> GetUnwrappedStreamingPrf(
    const KeyData& prf_key) {
  util::StatusOr<const KeyTypeInfoStore*> store =
      ConfigurationImpl::GetKeyTypeInfoStore(ConfigPrfForDeriver());
  if (!store.ok()) {
    return store.status();
  }
  util::StatusOr<const KeyTypeInfoStore::Info*> info =
      (*store)->Get(prf_key.type_url());
  if (!info.ok()) {
    return info.status();
  }
  return (*info)->GetPrimitive<StreamingPrf>(prf_key);
}

util::StatusOr<std::unique_ptr<KeysetDeriver>> PrfBasedDeriver::New(
    const KeyData& prf_key, const KeyTemplate& key_template) {
  // Create unwrapped StreamingPrf primitive from `prf_key`.
  util::StatusOr<std::unique_ptr<StreamingPrf>> streaming_prf =
      GetUnwrappedStreamingPrf(prf_key);
  if (!streaming_prf.ok()) {
    return streaming_prf.status();
  }

  util::Status status = RegisterProtoSerializations();
  if (!status.ok()) {
    return status;
  }

  // Validate `key_template`.
  std::unique_ptr<InputStream> randomness = (*streaming_prf)->ComputePrf("s");
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      DeriveKeysetHandle(key_template, *randomness);
  if (!handle.ok()) {
    return handle.status();
  }

  return {absl::WrapUnique<PrfBasedDeriver>(
      new PrfBasedDeriver(*std::move(streaming_prf), key_template))};
}

util::StatusOr<std::unique_ptr<KeysetHandle>> PrfBasedDeriver::DeriveKeyset(
    absl::string_view salt) const {
  std::unique_ptr<InputStream> randomness = streaming_prf_->ComputePrf(salt);
  return DeriveKeysetHandle(key_template_, *randomness);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
