// Copyright 2019 Google LLC
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

#ifndef TINK_KEYDERIVATION_KEY_DERIVATION_KEY_TEMPLATES_H_
#define TINK_KEYDERIVATION_KEY_DERIVATION_KEY_TEMPLATES_H_

#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// Methods to generate KeyTemplates for key derivation.
class KeyDerivationKeyTemplates {
 public:
  // Creates a key template for key derivation that uses a PRF to derive a key
  // that adheres to `derived_key_template`. The following must be true:
  //   (1) `prf_key_template` is a PRF key template, i.e.
  //         `keyset_handle->GetPrimitive<StreamingPrf>()` works.
  //   (2) `derived_key_template` describes a key type that supports derivation.
  //
  // The output prefix type of the derived key will match the output prefix type
  // of `derived_key_template`.
  //
  // This function verifies the newly created key template by creating a
  // KeysetDeriver primitive from it. This requires both the `prf_key_template`
  // and `derived_key_template` key types to be in the registry. It also
  // attempts to derive a key, returning an error on failure.
  static util::StatusOr<google::crypto::tink::KeyTemplate>
  CreatePrfBasedKeyTemplate(
      const google::crypto::tink::KeyTemplate& prf_key_template,
      const google::crypto::tink::KeyTemplate& derived_key_template);
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEYDERIVATION_KEY_DERIVATION_KEY_TEMPLATES_H_
