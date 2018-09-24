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

#ifndef TINK_NO_SECRET_KEYSET_HANDLE_H_
#define TINK_NO_SECRET_KEYSET_HANDLE_H_

#include "tink/keyset_handle.h"
#include "tink/keyset_reader.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// Creates a Keyset from a KeysetHandle as long as there is no secret key
// material in the keyset.
class NoSecretKeysetHandle {
 public:
  // Creates a KeysetHandle from a keyset or a failure if there is secret
  // material in the keyset.
  static crypto::tink::util::StatusOr<std::unique_ptr<KeysetHandle>> Get(
      google::crypto::tink::Keyset keyset);

 private:
  NoSecretKeysetHandle() = delete;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_NO_SECRET_KEYSET_HANDLE_H_
