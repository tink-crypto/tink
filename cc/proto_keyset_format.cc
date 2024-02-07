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

#include "tink/proto_keyset_format.h"

#include <ios>
#include <iostream>
#include <memory>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/binary_keyset_reader.h"
#include "tink/binary_keyset_writer.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/keyset_handle.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"
#include "tink/util/secret_proto.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

crypto::tink::util::StatusOr<KeysetHandle> ParseKeysetFromProtoKeysetFormat(
    absl::string_view serialized_keyset, SecretKeyAccessToken token) {
  crypto::tink::util::SecretProto<google::crypto::tink::Keyset> keyset_proto;
  if (!keyset_proto->ParseFromString(serialized_keyset)) {
    return util::Status(absl::StatusCode::kInternal,
                        "Failed to parse keyset");
  }
  util::StatusOr<std::vector<std::shared_ptr<const KeysetHandle::Entry>>>
      entries = KeysetHandle::GetEntriesFromKeyset(*keyset_proto);
  if (!entries.ok()) {
    return entries.status();
  }
  if (entries->size() != keyset_proto->key_size()) {
    return util::Status(absl::StatusCode::kInternal,
                        "Error converting keyset proto into key entries.");
  }
  return KeysetHandle(std::move(keyset_proto), *entries);
}

crypto::tink::util::StatusOr<util::SecretData>
SerializeKeysetToProtoKeysetFormat(const KeysetHandle& keyset_handle,
                                   SecretKeyAccessToken token) {
  const google::crypto::tink::Keyset& keyset =
      CleartextKeysetHandle::GetKeyset(keyset_handle);
  util::SecretData result(keyset.ByteSizeLong());
  if (!keyset.SerializeToArray(result.data(), result.size())) {
    return util::Status(absl::StatusCode::kInternal,
                        "Failed to serialize keyset");
  }
  return result;
}

crypto::tink::util::StatusOr<KeysetHandle>
ParseKeysetWithoutSecretFromProtoKeysetFormat(
    absl::string_view serialized_keyset) {
  std::string keyset_copy = std::string(serialized_keyset);
  crypto::tink::util::StatusOr<std::unique_ptr<KeysetHandle>> result =
    KeysetHandle::ReadNoSecret(keyset_copy);
  if (!result.ok()) {
    return result.status();
  }
  return std::move(**result);
}

crypto::tink::util::StatusOr<std::string>
SerializeKeysetWithoutSecretToProtoKeysetFormat(
    const KeysetHandle& keyset_handle) {
  std::stringbuf string_buf(std::ios_base::out);
  crypto::tink::util::StatusOr<std::unique_ptr<BinaryKeysetWriter>>
      keyset_writer = BinaryKeysetWriter::New(
          std::make_unique<std::ostream>(&string_buf));
  if (!keyset_writer.ok()) {
    return keyset_writer.status();
  }
  crypto::tink::util::Status status =
      keyset_handle.WriteNoSecret(keyset_writer->get());
  if (!status.ok()) {
    return status;
  }
  return string_buf.str();
}

}  // namespace tink
}  // namespace crypto

