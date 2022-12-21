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

#include "walkthrough/write_keyset.h"

// [START tink_walkthrough_write_keyset]
#include <fstream>
#include <memory>
#include <ostream>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/json_keyset_writer.h"
#include "tink/keyset_handle.h"
#include "tink/kms_client.h"
#include "tink/kms_clients.h"

namespace tink_walkthrough {

using ::crypto::tink::JsonKeysetWriter;
using ::crypto::tink::util::StatusOr;

// Writes a `keyset` to `output_stream` in JSON format; the keyset is encrypted
// through a KMS service using the KMS key `master_kms_key_uri`.
//
// Prerequisites for this example:
//  - Register AEAD implementations of Tink.
//  - Register a KMS client that can use `master_kms_key_uri`.
//  - Create a keyset and obtain a KeysetHandle to it.
crypto::tink::util::Status WriteEncryptedKeyset(
    const crypto::tink::KeysetHandle& keyset,
    std::unique_ptr<std::ostream> output_stream,
    absl::string_view master_kms_key_uri) {
  // Create a writer that will write the keyset to output_stream as JSON.
  StatusOr<std::unique_ptr<JsonKeysetWriter>> writer =
      JsonKeysetWriter::New(std::move(output_stream));
  if (!writer.ok()) return writer.status();
  // Get a KMS client for the given key URI.
  StatusOr<const crypto::tink::KmsClient*> kms_client =
      crypto::tink::KmsClients::Get(master_kms_key_uri);
  if (!kms_client.ok()) return kms_client.status();
  // Get an Aead primitive that uses the KMS service to encrypt/decrypt.
  StatusOr<std::unique_ptr<crypto::tink::Aead>> kms_aead =
      (*kms_client)->GetAead(master_kms_key_uri);
  if (!kms_aead.ok()) return kms_aead.status();
  return keyset.Write(writer->get(), **kms_aead);
}

}  // namespace tink_walkthrough
// [END tink_walkthrough_write_keyset]
