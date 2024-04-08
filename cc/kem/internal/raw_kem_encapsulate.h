// Copyright 2024 Google LLC
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

#ifndef TINK_KEM_INTERNAL_RAW_KEM_ENCAPSULATE_H_
#define TINK_KEM_INTERNAL_RAW_KEM_ENCAPSULATE_H_

#include <string>

#include "tink/restricted_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// A raw KEM encapsulation.
//
// This directly exposes the shared secret bytes.
struct RawKemEncapsulation {
  std::string ciphertext;
  RestrictedData shared_secret;
};

// A raw KEM encapsulation interface.
//
// The encapsulation method directly exposes shared secret bytes, rather than a
// higher-level KeysetHandle abstraction.
class RawKemEncapsulate {
 public:
  // Generates a new encapsulation, containing the ciphertext and the shared
  // secret bytes.
  virtual util::StatusOr<RawKemEncapsulation> Encapsulate() const = 0;

  virtual ~RawKemEncapsulate() = default;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEM_INTERNAL_RAW_KEM_ENCAPSULATE_H_
