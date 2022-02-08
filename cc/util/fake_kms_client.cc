// Copyright 2020 Google LLC
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
#include "tink/util/fake_kms_client.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/ascii.h"
#include "absl/strings/escaping.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "tink/aead/aead_key_templates.h"
#include "tink/binary_keyset_reader.h"
#include "tink/binary_keyset_writer.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/kms_client.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace test {

namespace {

using crypto::tink::ToStatusF;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::KeyTemplate;

static constexpr char kKeyUriPrefix[] = "fake-kms://";

// Returns the encoded keyset contained in 'key_uri'.
// If 'key_uri' does not refer to an fake KMS key, returns an empty string.
std::string GetEncodedKeyset(absl::string_view key_uri) {
  if (!absl::StartsWithIgnoreCase(key_uri, kKeyUriPrefix)) return "";
  return std::string(key_uri.substr(std::string(kKeyUriPrefix).length()));
}

}  // namespace


// static
StatusOr<std::unique_ptr<FakeKmsClient>> FakeKmsClient::New(
    absl::string_view key_uri, absl::string_view credentials_path) {
  std::unique_ptr<FakeKmsClient> client(new FakeKmsClient());

  if (!key_uri.empty()) {
    client->encoded_keyset_ = GetEncodedKeyset(key_uri);
    if (client->encoded_keyset_.empty()) {
      return ToStatusF(absl::StatusCode::kInvalidArgument,
                       "Key '%s' not supported", key_uri);
    }
  }
  return std::move(client);
}

bool FakeKmsClient::DoesSupport(absl::string_view key_uri) const {
  if (!encoded_keyset_.empty()) {
    return encoded_keyset_ == GetEncodedKeyset(key_uri);
  }
  return !GetEncodedKeyset(key_uri).empty();
}

StatusOr<std::unique_ptr<Aead>> FakeKmsClient::GetAead(
    absl::string_view key_uri) const {
  if (!DoesSupport(key_uri)) {
    if (!encoded_keyset_.empty()) {
      return ToStatusF(absl::StatusCode::kInvalidArgument,
                       "This client is bound to a different key, and cannot "
                       "use key '%s'.",
                       key_uri);
    } else {
      return ToStatusF(absl::StatusCode::kInvalidArgument,
                       "This client does not support key '%s'.", key_uri);
    }
  }
  std::string keyset;
  if (!absl::WebSafeBase64Unescape(GetEncodedKeyset(key_uri), &keyset)) {
    return util::Status(absl::StatusCode::kInvalidArgument, "Invalid Keyset");
  }
  auto reader_result = BinaryKeysetReader::New(keyset);
  if (!reader_result.ok()) {
    return reader_result.status();
  }
  auto handle_result =
      CleartextKeysetHandle::Read(std::move(reader_result.ValueOrDie()));
  if (!handle_result.ok()) {
    return handle_result.status();
  }
  return handle_result.ValueOrDie()->GetPrimitive<crypto::tink::Aead>();
}

Status FakeKmsClient::RegisterNewClient(absl::string_view key_uri,
                                        absl::string_view credentials_path) {
  auto client_result = FakeKmsClient::New(key_uri, credentials_path);
  if (!client_result.ok()) {
    return client_result.status();
  }

  return KmsClients::Add(std::move(client_result.ValueOrDie()));
}

StatusOr<std::string> FakeKmsClient::CreateFakeKeyUri() {
  // The key_uri contains an encoded keyset with a new Aes128Gcm key.
  const KeyTemplate& key_template = AeadKeyTemplates::Aes128Gcm();
  auto handle_result = KeysetHandle::GenerateNew(key_template);
  if (!handle_result.ok()) {
    return handle_result.status();
  }
  std::stringbuf keyset;
  auto writer_result =
      BinaryKeysetWriter::New(absl::make_unique<std::ostream>(&keyset));
  if (!writer_result.ok()) {
    return writer_result.status();
  }
  auto status = CleartextKeysetHandle::Write(writer_result.ValueOrDie().get(),
                                             *handle_result.ValueOrDie());
  if (!status.ok()) {
    return status;
  }
  std::string encoded_keyset;
  absl::WebSafeBase64Escape(keyset.str(), &encoded_keyset);
  return absl::StrCat(kKeyUriPrefix, encoded_keyset);
}

}  // namespace test
}  // namespace tink
}  // namespace crypto
