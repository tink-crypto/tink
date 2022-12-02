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

#ifndef TINK_PROTO_KEYSET_FORMAT_H_
#define TINK_PROTO_KEYSET_FORMAT_H_

#include <string>

#include "absl/strings/string_view.h"
#include "tink/keyset_handle.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/secret_data.h"

namespace crypto {
namespace tink {

// Serializes a keyset into a binary string in "ProtoKeysetFormat".
// This function can serialize both keyset with or without secret key material.
crypto::tink::util::StatusOr<util::SecretData>
SerializeKeysetToProtoKeysetFormat(const KeysetHandle& keyset_handle,
                                   SecretKeyAccessToken token);

// Parses a keyset from a binary string in "ProtoKeysetFormat".
// This function can parse both keyset with or without secret key material.
crypto::tink::util::StatusOr<KeysetHandle> ParseKeysetFromProtoKeysetFormat(
    absl::string_view serialized_keyset, SecretKeyAccessToken token);

// Serializes a keyset into a binary string in "ProtoKeysetFormat".
// This function will fail if the keyset contains secret key material.
crypto::tink::util::StatusOr<std::string>
SerializeKeysetWithoutSecretToProtoKeysetFormat(
    const KeysetHandle& keyset_handle);

// Parses a keyset from a binary string in "ProtoKeysetFormat".
// This function will fail if the keyset contains secret key material.
crypto::tink::util::StatusOr<KeysetHandle>
ParseKeysetWithoutSecretFromProtoKeysetFormat(
    absl::string_view serialized_keyset);


}  // namespace tink
}  // namespace crypto
#endif  // TINK_PROTO_KEYSET_FORMAT_H_
