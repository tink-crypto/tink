// Copyright 2022 Google LLC
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

#ifndef TINK_INSECURE_KEY_ACCESS_H_
#define TINK_INSECURE_KEY_ACCESS_H_

#include "tink/secret_key_access_token.h"

namespace crypto {
namespace tink {

class InsecureSecretKeyAccess {
 public:
  // Returns a `SecretKeyAccessToken`.
  //
  // The token can be used to access secret key material. Within Google, access
  // to this function is restricted by the build system. Outside of Google,
  // users can search their codebase for "InsecureSecretKeyAccess" to find
  // instances where it is used.
  static SecretKeyAccessToken Get() { return SecretKeyAccessToken(); }

 private:
  InsecureSecretKeyAccess() = default;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_INSECURE_KEY_ACCESS_H_
