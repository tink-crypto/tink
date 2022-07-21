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

#ifndef TINK_SECRET_KEY_ACCESS_TOKEN_H_
#define TINK_SECRET_KEY_ACCESS_TOKEN_H_

namespace crypto {
namespace tink {

class SecretKeyAccessToken {
 public:
  // Copyable and movable.
  SecretKeyAccessToken(const SecretKeyAccessToken& other) = default;
  SecretKeyAccessToken& operator=(const SecretKeyAccessToken& other) = default;
  SecretKeyAccessToken(SecretKeyAccessToken&& other) = default;
  SecretKeyAccessToken& operator=(SecretKeyAccessToken&& other) = default;

 private:
  // `InsecureKeyAccess` class requires access to the constructor.
  friend class InsecureSecretKeyAccess;

  SecretKeyAccessToken() = default;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SECRET_KEY_ACCESS_TOKEN_H_
