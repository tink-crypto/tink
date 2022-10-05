// Copyright 2022 Google LLC
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

#include "walkthrough/load_encrypted_keyset.h"

// [START tink_walkthrough_load_encrypted_keyset]
#include <iostream>
#include <memory>
#include <utility>

#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/json_keyset_reader.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_reader.h"
#include "tink/kms_client.h"
#include "tink/kms_clients.h"
#include "tink/util/statusor.h"

namespace tink_walkthrough {

using ::crypto::tink::KeysetHandle;
using ::crypto::tink::util::StatusOr;

// Loads a JSON-serialized keyset encrypted with a KSM
// `serialized_encrypted_keyset`. The decryption uses the KMS master key
// `master_key_uri`.
//
// Prerequisites for this example:
//  - Register AEAD implementations of Tink.
//  - Register a KMS client for the given URI prefix using KmsClients::Add.
//  - Create a KMS encrypted keyset, for example using Tinkey with Cloud KMS:
//
//    tinkey create-keyset --key-template AES128_GCM \
//      --out-format json --out encrypted_aead_keyset.json \
//      --master-key-uri gcp-kms://<KMS key uri> \
//      --credentials gcp_credentials.json
//
StatusOr<std::unique_ptr<KeysetHandle>> LoadKeyset(
    absl::string_view serialized_encrypted_keyset,
    absl::string_view master_key_uri) {
  // Get a KMS client for the given key URI.
  StatusOr<const crypto::tink::KmsClient*> kms_client =
      crypto::tink::KmsClients::Get(master_key_uri);
  if (!kms_client.ok()) {
    return kms_client.status();
  }
  // A KmsClient can return an Aead primitive.
  StatusOr<std::unique_ptr<crypto::tink::Aead>> kms_aead =
      (*kms_client)->GetAead(master_key_uri);
  if (!kms_aead.ok()) {
    return kms_aead.status();
  }
  // Use a JSON reader to read the encrypted keyset.
  StatusOr<std::unique_ptr<crypto::tink::KeysetReader>> reader =
      crypto::tink::JsonKeysetReader::New(serialized_encrypted_keyset);
  if (!reader.ok()) {
    return reader.status();
  }
  // Decrypt using the KMS, parse the keyset and retuns a handle to it.
  return KeysetHandle::Read(*std::move(reader), **kms_aead);
}

}  // namespace tink_walkthrough
// [END tink_walkthrough_load_encrypted_keyset]
