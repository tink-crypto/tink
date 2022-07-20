// Copyright 2018 Google Inc.
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

#ifndef TINK_DAEAD_DETERMINISTIC_AEAD_KEY_TEMPLATES_H_
#define TINK_DAEAD_DETERMINISTIC_AEAD_KEY_TEMPLATES_H_

#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// Pre-generated KeyTemplate for DeterministicAead key types.  One can use
// these templates to generate new KeysetHandle object with fresh keys.
// To generate a new keyset that contains a single AesGcmKey, one can do:
//
//   auto status = DeterministicAeadConfig::Register();
//   if (!status.ok()) { /* fail with error */ }
//   auto handle_result =
//       KeysetHandle::GenerateNew(DeterministicAeadKeyTemplates::Aes256Siv());
//   if (!handle_result.ok()) { /* fail with error */ }
//   auto keyset_handle = std::move(handle_result.value());
class DeterministicAeadKeyTemplates {
 public:
  // Returns a KeyTemplate that generates new instances of AesSivKey
  // with the following parameters:
  //   - key size: 64 bytes
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& Aes256Siv();
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_DAEAD_DETERMINISTIC_AEAD_KEY_TEMPLATES_H_
