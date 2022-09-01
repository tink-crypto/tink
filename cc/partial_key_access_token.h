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

#ifndef TINK_PARTIAL_KEY_ACCESS_TOKEN_H_
#define TINK_PARTIAL_KEY_ACCESS_TOKEN_H_

namespace crypto {
namespace tink {

class PartialKeyAccessToken {
 public:
  // Copyable and movable.
  PartialKeyAccessToken(const PartialKeyAccessToken& other) = default;
  PartialKeyAccessToken& operator=(const PartialKeyAccessToken& other) =
      default;
  PartialKeyAccessToken(PartialKeyAccessToken&& other) = default;
  PartialKeyAccessToken& operator=(PartialKeyAccessToken&& other) = default;

 private:
  // `GetPartialKeyAccess()` requires access to the constructor.
  friend PartialKeyAccessToken GetPartialKeyAccess();

  PartialKeyAccessToken() = default;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PARTIAL_KEY_ACCESS_TOKEN_H_
