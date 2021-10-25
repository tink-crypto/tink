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
///////////////////////////////////////////////////////////////////////////////
#include "tink/keyset_handle.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/internal/key_info.h"
#include "tink/keyset_reader.h"
#include "tink/keyset_writer.h"
#include "tink/registry.h"
#include "tink/util/errors.h"
#include "tink/util/keyset_util.h"
#include "proto/tink.pb.h"

using google::crypto::tink::EncryptedKeyset;
using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeysetInfo;
using google::crypto::tink::KeyTemplate;

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
  enc_keyset->set_encrypted_keyset(encrypt_result.ValueOrDie());
  return std::move(enc_keyset);
}

util::StatusOr<std::unique_ptr<Keyset>> Decrypt(
    const EncryptedKeyset& enc_keyset, const Aead& master_key_aead,
    absl::string_view associated_data) {
  auto decrypt_result =
      master_key_aead.Decrypt(enc_keyset.encrypted_keyset(), associated_data);
  if (!decrypt_result.ok()) return decrypt_result.status();
  auto keyset = absl::make_unique<Keyset>();
  if (!keyset->ParseFromString(decrypt_result.ValueOrDie())) {
    return util::Status(
        util::error::INVALID_ARGUMENT,
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

}  // anonymous namespace

// static
util::StatusOr<std::unique_ptr<KeysetHandle>> KeysetHandle::Read(
    std::unique_ptr<KeysetReader> reader, const Aead& master_key_aead) {
  return ReadWithAssociatedData(std::move(reader), master_key_aead, "");
}

// static
util::StatusOr<std::unique_ptr<KeysetHandle>>
KeysetHandle::ReadWithAssociatedData(std::unique_ptr<KeysetReader> reader,
                                     const Aead& master_key_aead,
                                     absl::string_view associated_data) {
  auto enc_keyset_result = reader->ReadEncrypted();
  if (!enc_keyset_result.ok()) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Error reading encrypted keyset data: %s",
                     enc_keyset_result.status().message());
  }

  auto keyset_result = Decrypt(*enc_keyset_result.ValueOrDie(), master_key_aead,
                               associated_data);
  if (!keyset_result.ok()) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Error decrypting encrypted keyset: %s",
                     keyset_result.status().message());
  }

  std::unique_ptr<KeysetHandle> handle(
      new KeysetHandle(std::move(keyset_result.ValueOrDie())));
  return std::move(handle);
}

// static
util::StatusOr<std::unique_ptr<KeysetHandle>> KeysetHandle::ReadNoSecret(
    const std::string& serialized_keyset) {
  Keyset keyset;
  if (!keyset.ParseFromString(serialized_keyset)) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Could not parse the input string as a Keyset-proto.");
  }
  util::Status validation = ValidateNoSecret(keyset);
  if (!validation.ok()) return validation;
  return absl::WrapUnique(new KeysetHandle(std::move(keyset)));
}

util::Status KeysetHandle::Write(KeysetWriter* writer,
                                 const Aead& master_key_aead) const {
  return WriteWithAssociatedData(writer, master_key_aead, "");
}

util::Status KeysetHandle::WriteWithAssociatedData(
    KeysetWriter* writer, const Aead& master_key_aead,
    absl::string_view associated_data) const {
  if (writer == nullptr) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Writer must be non-null");
  }
  auto encrypt_result = Encrypt(get_keyset(), master_key_aead, associated_data);
  if (!encrypt_result.ok()) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Encryption of the keyset failed: %s",
                     encrypt_result.status().message());
  }
  return writer->Write(*(encrypt_result.ValueOrDie()));
}

util::Status KeysetHandle::WriteNoSecret(KeysetWriter* writer) const {
  if (writer == nullptr) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Writer must be non-null");
  }

  util::Status validation = ValidateNoSecret(get_keyset());
  if (!validation.ok()) return validation;

  return writer->Write(get_keyset());
}

// static
util::StatusOr<std::unique_ptr<KeysetHandle>> KeysetHandle::GenerateNew(
    const KeyTemplate& key_template) {
  Keyset keyset;
  auto result = AddToKeyset(key_template, /*as_primary=*/true, &keyset);
  if (!result.ok()) {
    return result.status();
  }
  return absl::WrapUnique<KeysetHandle>(new KeysetHandle(std::move(keyset)));
}

util::StatusOr<std::unique_ptr<Keyset::Key>> ExtractPublicKey(
    const Keyset::Key& key) {
  if (key.key_data().key_material_type() != KeyData::ASYMMETRIC_PRIVATE) {
    return util::Status(
        util::error::INVALID_ARGUMENT,
        "Key material is not of type KeyData::ASYMMETRIC_PRIVATE");
  }
  auto key_data_result = Registry::GetPublicKeyData(key.key_data().type_url(),
                                                    key.key_data().value());
  if (!key_data_result.ok()) return key_data_result.status();
  auto public_key = absl::make_unique<Keyset::Key>(key);
  public_key->mutable_key_data()->Swap(key_data_result.ValueOrDie().get());
  return std::move(public_key);
}

util::StatusOr<std::unique_ptr<KeysetHandle>>
KeysetHandle::GetPublicKeysetHandle() const {
  std::unique_ptr<Keyset> public_keyset(new Keyset());
  for (const Keyset::Key& key : get_keyset().key()) {
    auto public_key_result = ExtractPublicKey(key);
    if (!public_key_result.ok()) return public_key_result.status();
    public_keyset->add_key()->Swap(public_key_result.ValueOrDie().get());
  }
  public_keyset->set_primary_key_id(get_keyset().primary_key_id());
  std::unique_ptr<KeysetHandle> handle(
      new KeysetHandle(std::move(public_keyset)));
  return std::move(handle);
}

crypto::tink::util::StatusOr<uint32_t> KeysetHandle::AddToKeyset(
    const google::crypto::tink::KeyTemplate& key_template, bool as_primary,
    Keyset* keyset) {
  if (key_template.output_prefix_type() ==
      google::crypto::tink::OutputPrefixType::UNKNOWN_PREFIX) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "key template has unknown prefix");
  }
  auto key_data_result = Registry::NewKeyData(key_template);
  if (!key_data_result.ok()) return key_data_result.status();
  auto key_data = std::move(key_data_result.ValueOrDie());
  Keyset::Key* key = keyset->add_key();
  uint32_t key_id = GenerateUnusedKeyId(*keyset);
  *(key->mutable_key_data()) = *key_data;
  key->set_status(google::crypto::tink::KeyStatusType::ENABLED);
  key->set_key_id(key_id);
  key->set_output_prefix_type(key_template.output_prefix_type());
  if (as_primary) {
    keyset->set_primary_key_id(key_id);
  }
  return key_id;
}

KeysetInfo KeysetHandle::GetKeysetInfo() const {
  return KeysetInfoFromKeyset(get_keyset());
}

KeysetHandle::KeysetHandle(Keyset keyset) : keyset_(std::move(keyset)) {}

KeysetHandle::KeysetHandle(std::unique_ptr<Keyset> keyset)
    : keyset_(std::move(*keyset)) {}

const Keyset& KeysetHandle::get_keyset() const { return keyset_; }

}  // namespace tink
}  // namespace crypto
