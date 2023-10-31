// Copyright 2017 Google Inc.
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

#include "tink/keyset_handle.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/log/check.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead.h"
#include "tink/config/global_registry.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/key_info.h"
#include "tink/internal/key_status_util.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/util.h"
#include "tink/key.h"
#include "tink/key_gen_configuration.h"
#include "tink/key_manager.h"
#include "tink/key_status.h"
#include "tink/keyset_reader.h"
#include "tink/keyset_writer.h"
#include "tink/registry.h"
#include "tink/restricted_data.h"
#include "tink/util/errors.h"
#include "tink/util/keyset_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

using google::crypto::tink::EncryptedKeyset;
using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeysetInfo;
using google::crypto::tink::KeyStatusType;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {

namespace {

util::StatusOr<std::unique_ptr<EncryptedKeyset>> Encrypt(
    const Keyset& keyset, const Aead& master_key_aead,
    absl::string_view associated_data) {
  auto encrypt_result =
      master_key_aead.Encrypt(keyset.SerializeAsString(), associated_data);
  if (!encrypt_result.ok()) return encrypt_result.status();
  auto enc_keyset = absl::make_unique<EncryptedKeyset>();
  enc_keyset->set_encrypted_keyset(encrypt_result.value());
  return std::move(enc_keyset);
}

util::StatusOr<std::unique_ptr<Keyset>> Decrypt(
    const EncryptedKeyset& enc_keyset, const Aead& master_key_aead,
    absl::string_view associated_data) {
  auto decrypt_result =
      master_key_aead.Decrypt(enc_keyset.encrypted_keyset(), associated_data);
  if (!decrypt_result.ok()) return decrypt_result.status();
  auto keyset = absl::make_unique<Keyset>();
  if (!keyset->ParseFromString(decrypt_result.value())) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Could not parse the decrypted data as a Keyset-proto.");
  }
  return std::move(keyset);
}

util::Status ValidateNoSecret(const Keyset& keyset) {
  for (const Keyset::Key& key : keyset.key()) {
    if (key.key_data().key_material_type() == KeyData::UNKNOWN_KEYMATERIAL ||
        key.key_data().key_material_type() == KeyData::SYMMETRIC ||
        key.key_data().key_material_type() == KeyData::ASYMMETRIC_PRIVATE) {
      return util::Status(
          absl::StatusCode::kFailedPrecondition,
          "Cannot create KeysetHandle with secret key material from "
          "potentially unencrypted source.");
    }
  }
  return util::OkStatus();
}

util::StatusOr<internal::ProtoKeySerialization> ToProtoKeySerialization(
    Keyset::Key key) {
  absl::optional<int> id_requirement = absl::nullopt;
  if (key.output_prefix_type() != OutputPrefixType::RAW) {
    id_requirement = key.key_id();
  }

  return internal::ProtoKeySerialization::Create(
      key.key_data().type_url(),
      RestrictedData(key.key_data().value(), InsecureSecretKeyAccess::Get()),
      key.key_data().key_material_type(), key.output_prefix_type(),
      id_requirement);
}

}  // anonymous namespace

util::Status KeysetHandle::ValidateAt(int index) const {
  const Keyset::Key& proto_key = get_keyset().key(index);
  OutputPrefixType output_prefix_type = proto_key.output_prefix_type();
  absl::optional<int> id_requirement = absl::nullopt;
  if (output_prefix_type != OutputPrefixType::RAW) {
    id_requirement = proto_key.key_id();
  }

  if (!internal::IsPrintableAscii(proto_key.key_data().type_url())) {
    return util::Status(absl::StatusCode::kFailedPrecondition,
                        "Non-printable ASCII character in type URL.");
  }

  util::StatusOr<KeyStatus> key_status =
      internal::FromKeyStatusType(proto_key.status());
  if (!key_status.ok()) return key_status.status();

  return util::OkStatus();
}

util::Status KeysetHandle::Validate() const {
  int num_primary = 0;
  const Keyset& keyset = get_keyset();

  for (int i = 0; i < size(); ++i) {
    util::Status status = ValidateAt(i);
    if (!status.ok()) return status;

    Keyset::Key proto_key = keyset.key(i);
    if (proto_key.key_id() == keyset.primary_key_id()) {
      ++num_primary;
      if (proto_key.status() != KeyStatusType::ENABLED) {
        return util::Status(absl::StatusCode::kFailedPrecondition,
                            "Keyset has primary that is not enabled");
      }
    }
  }

  if (num_primary < 1) {
    return util::Status(absl::StatusCode::kFailedPrecondition,
                        "Keyset has no primary");
  }
  if (num_primary > 1) {
    return util::Status(absl::StatusCode::kFailedPrecondition,
                        "Keyset has more than one primary");
  }

  return util::OkStatus();
}

KeysetHandle::Entry KeysetHandle::GetPrimary() const {
  util::Status validation = Validate();
  CHECK_OK(validation);

  const Keyset& keyset = get_keyset();
  for (int i = 0; i < keyset.key_size(); ++i) {
    if (keyset.key(i).key_id() == keyset.primary_key_id()) {
      return (*this)[i];
    }
  }

  // Since keyset handle was validated, it should have a valid primary key.
  internal::LogFatal("Keyset handle should have a valid primary key.");
}

KeysetHandle::Entry KeysetHandle::operator[](int index) const {
  CHECK(index >= 0 && index < size())
      << "Invalid index " << index << " for keyset of size " << size();

  if (!entries_.empty() && entries_.size() > index) {
    return *entries_[index];
  }
  // Since `entries_` has not been populated, the entry must be created on
  // demand from the key proto entry at `index` in `keyset_`. This special
  // case will no longer be necessary after `keyset_` has been removed from the
  // `KeysetHandle` class.
  //
  // TODO(b/277792846): Remove after transition to rely solely on
  // `KeysetHandle::Entry`.
  return CreateEntryAt(index);
}

KeysetHandle::Entry KeysetHandle::CreateEntryAt(int index) const {
  CHECK(index >= 0 && index < size())
      << "Invalid index " << index << " for keyset of size " << size();

  util::Status validation = ValidateAt(index);
  CHECK_OK(validation);

  Keyset keyset = get_keyset();
  util::StatusOr<Entry> entry =
      CreateEntry(keyset.key(index), keyset.primary_key_id());
  // Status should be OK since this keyset handle has been validated.
  CHECK_OK(entry.status());
  return *entry;
}

util::StatusOr<KeysetHandle::Entry> KeysetHandle::CreateEntry(
    const Keyset::Key& proto_key, uint32_t primary_key_id) {
  util::StatusOr<internal::ProtoKeySerialization> serialization =
      ToProtoKeySerialization(proto_key);
  if (!serialization.ok()) {
    return serialization.status();
  }

  util::StatusOr<std::shared_ptr<const Key>> key =
      internal::MutableSerializationRegistry::GlobalInstance()
          .ParseKeyWithLegacyFallback(*serialization,
                                      InsecureSecretKeyAccess::Get());
  if (!key.ok()) {
    return key.status();
  }

  util::StatusOr<KeyStatus> key_status =
      internal::FromKeyStatusType(proto_key.status());
  if (!key_status.ok()) {
    return key_status.status();
  }

  return Entry(*std::move(key), *key_status, proto_key.key_id(),
               proto_key.key_id() == primary_key_id);
}

util::StatusOr<std::unique_ptr<KeysetHandle>> KeysetHandle::Read(
    std::unique_ptr<KeysetReader> reader, const Aead& master_key_aead,
    const absl::flat_hash_map<std::string, std::string>&
        monitoring_annotations) {
  return ReadWithAssociatedData(std::move(reader), master_key_aead,
                                /*associated_data=*/"", monitoring_annotations);
}

util::StatusOr<std::unique_ptr<KeysetHandle>>
KeysetHandle::ReadWithAssociatedData(
    std::unique_ptr<KeysetReader> reader, const Aead& master_key_aead,
    absl::string_view associated_data,
    const absl::flat_hash_map<std::string, std::string>&
        monitoring_annotations) {
  util::StatusOr<std::unique_ptr<EncryptedKeyset>> enc_keyset_result =
      reader->ReadEncrypted();
  if (!enc_keyset_result.ok()) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "Error reading encrypted keyset data: %s",
                     enc_keyset_result.status().message());
  }

  auto keyset_result =
      Decrypt(*enc_keyset_result.value(), master_key_aead, associated_data);
  if (!keyset_result.ok()) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "Error decrypting encrypted keyset: %s",
                     keyset_result.status().message());
  }
  util::StatusOr<std::vector<std::shared_ptr<const Entry>>> entries =
      GetEntriesFromKeyset(**keyset_result);
  if (!entries.ok()) {
    return entries.status();
  }
  if (entries->size() != (*keyset_result)->key_size()) {
    return util::Status(absl::StatusCode::kInternal,
                        "Error converting keyset proto into key entries.");
  }
  return absl::WrapUnique(new KeysetHandle(*std::move(keyset_result), *entries,
                                           monitoring_annotations));
}

util::StatusOr<std::unique_ptr<KeysetHandle>> KeysetHandle::ReadNoSecret(
    const std::string& serialized_keyset,
    const absl::flat_hash_map<std::string, std::string>&
        monitoring_annotations) {
  Keyset keyset;
  if (!keyset.ParseFromString(serialized_keyset)) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Could not parse the input string as a Keyset-proto.");
  }
  util::Status validation = ValidateNoSecret(keyset);
  if (!validation.ok()) {
    return validation;
  }
  util::StatusOr<std::vector<std::shared_ptr<const Entry>>> entries =
      GetEntriesFromKeyset(keyset);
  if (!entries.ok()) {
    return entries.status();
  }
  if (entries->size() != keyset.key_size()) {
    return util::Status(absl::StatusCode::kInternal,
                        "Error converting keyset proto into key entries.");
  }
  return absl::WrapUnique(
      new KeysetHandle(std::move(keyset), *entries, monitoring_annotations));
}

util::Status KeysetHandle::Write(KeysetWriter* writer,
                                 const Aead& master_key_aead) const {
  return WriteWithAssociatedData(writer, master_key_aead, "");
}

util::Status KeysetHandle::WriteWithAssociatedData(
    KeysetWriter* writer, const Aead& master_key_aead,
    absl::string_view associated_data) const {
  if (writer == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Writer must be non-null");
  }
  auto encrypt_result = Encrypt(get_keyset(), master_key_aead, associated_data);
  if (!encrypt_result.ok()) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "Encryption of the keyset failed: %s",
                     encrypt_result.status().message());
  }
  return writer->Write(*(encrypt_result.value()));
}

util::Status KeysetHandle::WriteNoSecret(KeysetWriter* writer) const {
  if (writer == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Writer must be non-null");
  }

  util::Status validation = ValidateNoSecret(get_keyset());
  if (!validation.ok()) return validation;

  return writer->Write(get_keyset());
}

util::StatusOr<std::unique_ptr<KeysetHandle>> KeysetHandle::GenerateNew(
    const KeyTemplate& key_template, const KeyGenConfiguration& config,
    const absl::flat_hash_map<std::string, std::string>&
        monitoring_annotations) {
  auto handle =
      absl::WrapUnique(new KeysetHandle(Keyset(), monitoring_annotations));
  util::StatusOr<uint32_t> const result =
      handle->AddKey(key_template, /*as_primary=*/true, config);
  if (!result.ok()) {
    return result.status();
  }
  return std::move(handle);
}

util::StatusOr<std::unique_ptr<KeysetHandle>> KeysetHandle::GenerateNew(
    const KeyTemplate& key_template, const KeyGenConfiguration& config) {
  return GenerateNew(key_template, config, /*monitoring_annotations=*/{});
}

util::StatusOr<std::unique_ptr<Keyset::Key>> ExtractPublicKey(
    const Keyset::Key& key, const KeyGenConfiguration& config) {
  if (key.key_data().key_material_type() != KeyData::ASYMMETRIC_PRIVATE) {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        "Key material is not of type KeyData::ASYMMETRIC_PRIVATE");
  }

  util::StatusOr<std::unique_ptr<KeyData>> key_data;
  if (internal::KeyGenConfigurationImpl::IsInGlobalRegistryMode(config)) {
    key_data = Registry::GetPublicKeyData(key.key_data().type_url(),
                                          key.key_data().value());
  } else {
    util::StatusOr<const internal::KeyTypeInfoStore*> key_type_info_store =
        internal::KeyGenConfigurationImpl::GetKeyTypeInfoStore(config);
    if (!key_type_info_store.ok()) {
      return key_type_info_store.status();
    }
    util::StatusOr<const internal::KeyTypeInfoStore::Info*> key_type_info =
        (*key_type_info_store)->Get(key.key_data().type_url());
    if (!key_type_info.ok()) {
      return key_type_info.status();
    }
    auto factory = dynamic_cast<const PrivateKeyFactory*>(
        &(*key_type_info)->key_factory());
    if (factory == nullptr) {
      return ToStatusF(
          absl::StatusCode::kInvalidArgument,
          "KeyManager for type '%s' does not have a PrivateKeyFactory.",
          key.key_data().type_url());
    }
    key_data = factory->GetPublicKeyData(key.key_data().value());
  }
  if (!key_data.ok()) {
    return key_data.status();
  }

  auto public_key = absl::make_unique<Keyset::Key>(key);
  public_key->mutable_key_data()->Swap(key_data->get());
  return std::move(public_key);
}

util::StatusOr<std::unique_ptr<KeysetHandle>>
KeysetHandle::GetPublicKeysetHandle(const KeyGenConfiguration& config) const {
  auto public_keyset = std::make_unique<Keyset>();
  for (const Keyset::Key& key : get_keyset().key()) {
    auto public_key_result = ExtractPublicKey(key, config);
    if (!public_key_result.ok()) return public_key_result.status();
    public_keyset->add_key()->Swap(public_key_result.value().get());
  }
  public_keyset->set_primary_key_id(get_keyset().primary_key_id());
  util::StatusOr<std::vector<std::shared_ptr<const Entry>>> entries =
      GetEntriesFromKeyset(*public_keyset);
  if (!entries.ok()) {
    return entries.status();
  }
  if (entries->size() != public_keyset->key_size()) {
    return util::Status(absl::StatusCode::kInternal,
                        "Error converting keyset proto into key entries.");
  }
  return absl::WrapUnique<KeysetHandle>(
      new KeysetHandle(std::move(public_keyset), *entries));
}

crypto::tink::util::StatusOr<uint32_t> KeysetHandle::AddToKeyset(
    const google::crypto::tink::KeyTemplate& key_template, bool as_primary,
    const KeyGenConfiguration& config, Keyset* keyset) {
  if (key_template.output_prefix_type() ==
      google::crypto::tink::OutputPrefixType::UNKNOWN_PREFIX) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "key template has unknown prefix");
  }

  // Generate new key data.
  util::StatusOr<std::unique_ptr<KeyData>> key_data;
  if (internal::KeyGenConfigurationImpl::IsInGlobalRegistryMode(config)) {
    key_data = Registry::NewKeyData(key_template);
  } else {
    util::StatusOr<const internal::KeyTypeInfoStore*> key_type_info_store =
        internal::KeyGenConfigurationImpl::GetKeyTypeInfoStore(config);
    if (!key_type_info_store.ok()) {
      return key_type_info_store.status();
    }
    util::StatusOr<const internal::KeyTypeInfoStore::Info*> key_type_info =
        (*key_type_info_store)->Get(key_template.type_url());
    if (!key_type_info.ok()) {
      return key_type_info.status();
    }
    key_data = (*key_type_info)->key_factory().NewKeyData(key_template.value());
  }
  if (!key_data.ok()) {
    return key_data.status();
  }

  // Add and fill in new key in `keyset`.
  Keyset::Key* key = keyset->add_key();
  *(key->mutable_key_data()) = *std::move(key_data).value();
  key->set_status(KeyStatusType::ENABLED);
  key->set_output_prefix_type(key_template.output_prefix_type());

  uint32_t key_id = GenerateUnusedKeyId(*keyset);
  key->set_key_id(key_id);
  if (as_primary) {
    keyset->set_primary_key_id(key_id);
  }
  return key_id;
}

crypto::tink::util::StatusOr<uint32_t> KeysetHandle::AddKey(
    const google::crypto::tink::KeyTemplate& key_template, bool as_primary,
    const KeyGenConfiguration& config) {
  util::StatusOr<uint32_t> id =
      AddToKeyset(key_template, as_primary, config, &keyset_);
  if (!id.ok()) {
    return id.status();
  }
  util::StatusOr<const Entry> entry = CreateEntry(
      keyset_.key(keyset_.key_size() - 1), keyset_.primary_key_id());
  if (!entry.ok()) {
    return entry.status();
  }
  entries_.push_back(std::make_shared<const Entry>(*entry));
  return *id;
}

KeysetInfo KeysetHandle::GetKeysetInfo() const {
  return KeysetInfoFromKeyset(get_keyset());
}

util::StatusOr<std::vector<std::shared_ptr<const KeysetHandle::Entry>>>
KeysetHandle::GetEntriesFromKeyset(const Keyset& keyset) {
  std::vector<std::shared_ptr<const Entry>> entries;
  for (const Keyset::Key& key : keyset.key()) {
    util::StatusOr<const Entry> entry =
        CreateEntry(key, keyset.primary_key_id());
    if (!entry.ok()) {
      return entry.status();
    }
    entries.push_back(std::make_shared<const Entry>(*entry));
  }
  return entries;
}

}  // namespace tink
}  // namespace crypto
