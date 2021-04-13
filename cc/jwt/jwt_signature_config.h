// Copyright 2021 Google LLC
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

#ifndef TINK_JWT_JWT_SIGNATURE_CONFIG_H_
#define TINK_JWT_JWT_SIGNATURE_CONFIG_H_

#include "absl/base/macros.h"
#include "tink/util/status.h"
#include "proto/config.pb.h"

namespace crypto {
namespace tink {

// Registers JwtPublicKeySign and JwtPublicKeyVerify primitive wrapper and key
// managers for all JwtPublicKeySign and JwtPublicKeyVerify key types from the
// current Tink release.
crypto::tink::util::Status JwtSignatureRegister();

}  // namespace tink
}  // namespace crypto

#endif  // TINK_JWT_JWT_SIGNATURE_CONFIG_H_
