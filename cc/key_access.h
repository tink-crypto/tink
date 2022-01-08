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

#ifndef THIRD_PARTY_TINK_KEY_ACCESS_H_
#define THIRD_PARTY_TINK_KEY_ACCESS_H_

namespace crypto {
namespace tink {

class KeyAccess {
 public:
  static KeyAccess PublicAccess() {
    KeyAccess token(false);
    return token;
  }

  const bool CanAccessSecret() { return can_access_secret_; }

  // KeyAccess objects are copiable and movable.
  KeyAccess(const KeyAccess&) = default;
  KeyAccess& operator=(const KeyAccess&) = default;
  KeyAccess(KeyAccess&& other) = default;
  KeyAccess& operator=(KeyAccess&& other) = default;

 private:
  KeyAccess() = delete;
  explicit KeyAccess(bool can_access_secret)
      : can_access_secret_(can_access_secret) {}
  friend class SecretKeyAccess;
  bool can_access_secret_;
};

}  // namespace tink
}  // namespace crypto

#endif  // THIRD_PARTY_TINK_KEY_ACCESS_H_
