// Copyright 2021 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#ifndef THIRD_PARTY_TINK_SECRET_KEY_ACCESS_H_
#define THIRD_PARTY_TINK_SECRET_KEY_ACCESS_H_

#include "tink/key_access.h"

namespace crypto {
namespace tink {

class SecretKeyAccess {
 public:
  static KeyAccess SecretAccess() { return KeyAccess(true); }
};

}  // namespace tink
}  // namespace crypto

#endif  // THIRD_PARTY_TINK_SECRET_KEY_ACCESS_H_
