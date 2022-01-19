// Copyright 2021 Google LLC
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

#ifndef TINK_JWT_JWK_SET_CONVERTER_H_
#define TINK_JWT_JWK_SET_CONVERTER_H_

#include "absl/strings/string_view.h"
#include "tink/keyset_handle.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Converts a Json Web Key (JWK) set into a Tink KeysetHandle.
//
// It requires that all keys in the set have the "alg" field set. Currently,
// only public keys for algorithms RS256, RS384, RS512, ES256, ES384 and ES512
// are supported.
//
// JWK is defined in https://www.rfc-editor.org/rfc/rfc7517.txt.
util::StatusOr<std::unique_ptr<KeysetHandle>> JwkSetToPublicKeysetHandle(
    absl::string_view jwk_set);

// Converts a Tink KeysetHandle with JWT keys into a Json Web Key (JWK) set.
//
// Currently only public keys for algorithms ES256, ES384 and ES512 are
// supported.
//
// JWK is defined in https://www.rfc-editor.org/rfc/rfc7517.txt.
util::StatusOr<std::string> JwkSetFromPublicKeysetHandle(
    const KeysetHandle& keyset_handle);

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWK_SET_CONVERTER_H_
