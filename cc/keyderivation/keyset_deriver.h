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

#ifndef TINK_KEYDERIVATION_KEYSET_DERIVER_H_
#define TINK_KEYDERIVATION_KEYSET_DERIVER_H_

#include <memory>

#include "absl/strings/string_view.h"
#include "tink/keyset_handle.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// KeysetDeriver is the interface used to derive new keysets based on an
// additional input, the salt.
//
// The salt is used to create the keyset using a pseudorandom function.
// Implementations must be indistinguishable from ideal KeysetDerivers, which,
// for every salt, generates a new random keyset and caches it.
class KeysetDeriver {
 public:
  virtual crypto::tink::util::StatusOr<std::unique_ptr<KeysetHandle>>
  DeriveKeyset(absl::string_view salt) const = 0;

  virtual ~KeysetDeriver() = default;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEYDERIVATION_KEYSET_DERIVER_H_
