// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/internal/keyset_handle_builder_entry.h"

#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/key_status_util.h"
#include "tink/internal/legacy_proto_key.h"
#include "tink/internal/legacy_proto_parameters.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/key_status.h"
#include "tink/registry.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::Keyset;
using ::google::crypto::tink::KeyStatusType;

Keyset::Key ToKeysetKey(int id, KeyStatusType status,
                        const ProtoKeySerialization& serialization) {
  KeyData key_data;
  key_data.set_type_url(std::string(serialization.TypeUrl()));
  // OSS proto library complains if serialized key is not converted to string.
  key_data.set_value(std::string(serialization.SerializedKeyProto().GetSecret(
      InsecureSecretKeyAccess::Get())));
  key_data.set_key_material_type(serialization.KeyMaterialType());
  Keyset::Key key;
  key.set_status(status);
  key.set_key_id(id);
  key.set_output_prefix_type(serialization.GetOutputPrefixType());
  *key.mutable_key_data() = key_data;
  return key;
}

util::StatusOr<Keyset::Key> CreateKeysetKeyFromLegacyProtoParameters(
    const LegacyProtoParameters& parameters, int id, KeyStatusType status) {
  ProtoParametersSerialization serialization = parameters.Serialization();
  util::StatusOr<std::unique_ptr<KeyData>> key_data =
      Registry::NewKeyData(serialization.GetKeyTemplate());
  if (!key_data.ok()) return key_data.status();

  Keyset::Key key;
  key.set_status(status);
  key.set_key_id(id);
  key.set_output_prefix_type(
      serialization.GetKeyTemplate().output_prefix_type());
  *key.mutable_key_data() = **key_data;
  return key;
}

util::StatusOr<Keyset::Key> CreateKeysetKeyFromLegacyProtoKey(
    const LegacyProtoKey& key, int id, KeyStatusType status) {
  util::StatusOr<const ProtoKeySerialization*> serialized_key =
      key.Serialization(InsecureSecretKeyAccess::Get());
  if (!serialized_key.ok()) return serialized_key.status();

  absl::optional<int> id_requirement = (*serialized_key)->IdRequirement();
  if (id_requirement.has_value() && *id_requirement != id) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Wrong ID set for key with ID requirement.");
  }
  return ToKeysetKey(id, status, **serialized_key);
}

}  // namespace

void KeysetHandleBuilderEntry::SetFixedId(int id) {
  strategy_.strategy = KeyIdStrategyEnum::kFixedId;
  strategy_.id_requirement = id;
}

void KeysetHandleBuilderEntry::SetRandomId() {
  strategy_.strategy = KeyIdStrategyEnum::kRandomId;
  strategy_.id_requirement = absl::nullopt;
}

util::StatusOr<Keyset::Key> KeyEntry::CreateKeysetKey(int id) {
  util::StatusOr<KeyStatusType> key_status = ToKeyStatusType(key_status_);
  if (!key_status.ok()) return key_status.status();

  if (GetKeyIdRequirement().has_value() && GetKeyIdRequirement() != id) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Requested id does not match id requirement.");
  }

  // TODO(b/242162436): Add support for more than LegacyProtoKey.
  const LegacyProtoKey& key = dynamic_cast<const LegacyProtoKey&>(*key_);
  return CreateKeysetKeyFromLegacyProtoKey(key, id, *key_status);
}

util::StatusOr<Keyset::Key> ParametersEntry::CreateKeysetKey(int id) {
  util::StatusOr<KeyStatusType> key_status = ToKeyStatusType(key_status_);
  if (!key_status.ok()) return key_status.status();

  if (GetKeyIdRequirement().has_value() && GetKeyIdRequirement() != id) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Requested id does not match id requirement.");
  }

  // TODO(b/242162436): Add support for more than LegacyProtoParameters.
  const LegacyProtoParameters& params =
      dynamic_cast<const LegacyProtoParameters&>(*parameters_);
  return CreateKeysetKeyFromLegacyProtoParameters(params, id, *key_status);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
