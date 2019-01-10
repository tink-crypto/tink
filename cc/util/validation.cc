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

#include "tink/util/validation.h"

#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "proto/tink.pb.h"


namespace crypto {
namespace tink {

// TODO(przydatek): add more validation checks

util::Status ValidateAesKeySize(uint32_t key_size) {
  if (key_size != 16 && key_size != 32) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "AES key has %d bytes; supported sizes: 16 or 32 bytes.",
                     key_size);
  }
  return util::Status::OK;
}

util::Status ValidateKeyset(const google::crypto::tink::Keyset& keyset) {
  if (keyset.key_size() < 1) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "A valid keyset must contain at least one key.");
  }
  return util::Status::OK;
}

util::Status ValidateVersion(uint32_t candidate, uint32_t max_expected) {
  if (candidate > max_expected) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key has version '%d'; "
                     "only keys with version in range [0..%d] are supported.",
                     candidate, max_expected);
  }
  return util::Status::OK;
}


}  // namespace tink
}  // namespace crypto
