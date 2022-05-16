// Copyright 2019 Google LLC
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

#ifndef TINK_PRF_PRF_KEY_TEMPLATES_H_
#define TINK_PRF_PRF_KEY_TEMPLATES_H_

#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// Pre-generated KeyTemplate for Prf key types. One can use these templates
// to generate new KeysetHandle object with fresh keys.
// To generate a new keyset that contains a single HkdfPrfKey, one can do:
//
//   auto handle_result =
//       KeysetHandle::GenerateNew(PrfKeyTemplates::HkdfSha256());
//   if (!handle_result.ok()) { /* fail with error */ }
//   auto keyset_handle = std::move(handle_result.value());
class PrfKeyTemplates {
 public:
  // Hkdf
  //  * Hash function: SHA256
  //  * Key size: 256 bit
  //  * Salt: empty
  static const google::crypto::tink::KeyTemplate& HkdfSha256();
  static const google::crypto::tink::KeyTemplate& HmacSha256();
  static const google::crypto::tink::KeyTemplate& HmacSha512();
  static const google::crypto::tink::KeyTemplate& AesCmac();
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PRF_PRF_KEY_TEMPLATES_H_
