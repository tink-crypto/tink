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

#ifndef TINK_KEY_STATUS_H_
#define TINK_KEY_STATUS_H_

namespace crypto {
namespace tink {

// Enum representation of KeyStatusType in tink/proto/tink.proto. Using an
// enum class prevents unintentional implicit conversions.
enum class KeyStatus : int {
  kEnabled = 1,    // Can be used for cryptographic operations.
  kDisabled = 2,   // Cannot be used (but can become kEnabled again).
  kDestroyed = 3,  // Key data does not exist in this Keyset any more.
  // Added to guard from failures that may be caused by future expansions.
  kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEY_STATUS_H_
