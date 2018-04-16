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

#include "absl/memory/memory.h"
#include "tink/aead.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_reader.h"
#include "tink/keyset_writer.h"
#include "tink/util/errors.h"
#include "proto/tink.pb.h"

using google::crypto::tink::EncryptedKeyset;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeyTemplate;


namespace crypto {
namespace tink {

namespace {

util::StatusOr<std::unique_ptr<EncryptedKeyset>>
Encrypt(const Keyset& keyset, const Aead& master_key_aead) {
  auto encrypt_result = master_key_aead.Encrypt(
          keyset.SerializeAsString(), /* associated_data= */ "");
  if (!encrypt_result.ok()) return encrypt_result.status();
  auto enc_keyset = absl::make_unique<EncryptedKeyset>();
  enc_keyset->set_encrypted_keyset(encrypt_result.ValueOrDie());
  return std::move(enc_keyset);
}

util::StatusOr<std::unique_ptr<Keyset>>
Decrypt(const EncryptedKeyset& enc_keyset, const Aead& master_key_aead) {
  auto decrypt_result = master_key_aead.Decrypt(
          enc_keyset.encrypted_keyset(), /* associated_data= */ "");
  if (!decrypt_result.ok()) return decrypt_result.status();
  auto keyset = absl::make_unique<Keyset>();
  if (!keyset->ParseFromString(decrypt_result.ValueOrDie())) {
    return util::Status(util::error::INVALID_ARGUMENT,
        "Could not parse the decrypted data as a Keyset-proto.");
  }
  return std::move(keyset);
}

}  // anonymous namespace

// static
util::StatusOr<std::unique_ptr<KeysetHandle>> KeysetHandle::Read(
    std::unique_ptr<KeysetReader> reader, const Aead& master_key_aead) {
  auto enc_keyset_result = reader->ReadEncrypted();
  if (!enc_keyset_result.ok()) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Error reading encrypted keyset data: %s",
                     enc_keyset_result.status().error_message().c_str());
  }

  auto keyset_result =
      Decrypt(*enc_keyset_result.ValueOrDie(), master_key_aead);
  if (!keyset_result.ok()) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Error decrypting encrypted keyset: %s",
                     keyset_result.status().error_message().c_str());
  }

  std::unique_ptr<KeysetHandle> handle(
      new KeysetHandle(std::move(keyset_result.ValueOrDie())));
  return std::move(handle);
}

util::Status KeysetHandle::WriteEncrypted(const Aead& master_key_aead,
                                          KeysetWriter* writer) {
  if (writer == nullptr) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Writer must be non-null");
  }
  auto encrypt_result = Encrypt(get_keyset(), master_key_aead);
  if (!encrypt_result.ok()) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Encryption of the keyset failed: %s",
                     encrypt_result.status().error_message().c_str());
  }
  return writer->Write(*(encrypt_result.ValueOrDie().get()));
}

// static
util::StatusOr<std::unique_ptr<KeysetHandle>> KeysetHandle::GenerateNew(
    const KeyTemplate& key_template) {
  return util::Status(util::error::UNIMPLEMENTED,
      "Generation of new keysets from templates is not implemented yet.");
}

KeysetHandle::KeysetHandle(std::unique_ptr<Keyset> keyset)
    : keyset_(std::move(keyset)) {}

const Keyset& KeysetHandle::get_keyset() const {
  return *(keyset_.get());
}

}  // namespace tink
}  // namespace crypto
