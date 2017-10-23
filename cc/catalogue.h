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

#ifndef TINK_CATALOGUE_H_
#define TINK_CATALOGUE_H_

#include "cc/key_manager.h"
#include "cc/util/statusor.h"

namespace crypto {
namespace tink {

// A catalogue of KeyManager objects.
//
// It is basically a map from a (key type, primitive name)-tuple to
// KeyManager-objects, that determine the implementation that handles
// the keys of the given key type.
//
// Tink includes default per-primitive catalogues, but it also
// supports custom catalogues to enable user-defined configuration of
// run-time environment via Registry.
template <class P>
class Catalogue {
 public:
  // Returns a key manager for the given 'type_url', 'primitive_name',
  // and version at least 'min_version' (if any found).
  // Caller owns the returned manager.
  virtual crypto::tink::util::StatusOr<std::unique_ptr<KeyManager<P>>>
      GetKeyManager(const std::string& type_url,
                    const std::string& primitive_name,
                    uint32_t min_version) const = 0;

  virtual ~Catalogue() {}
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_CATALOGUE_H_
