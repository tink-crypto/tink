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

#ifndef TINK_MAC_MAC_KEY_TEMPLATES_H_
#define TINK_MAC_MAC_KEY_TEMPLATES_H_

#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// Pre-generated KeyTemplate for Mac key types. One can use these templates
// to generate a new KeysetHandle object with fresh keys.
// To generate a new keyset that contains a single HmacKey, one can do:
//
//   auto status = MacConfig::Register();
//   if (!status.ok()) { /* fail with error */ }
//   auto handle_result =
//       KeysetHandle::GenerateNew(MacKeyTemplates::HmacSha256HalfSizeTag());
//   if (!handle_result.ok()) { /* fail with error */ }
//   auto keyset_handle = std::move(handle_result.value());
class MacKeyTemplates {
 public:
  // Returns a KeyTemplate that generates new instances of HmacKey
  // with the following parameters:
  //   - key size: 32 bytes
  //   - tag size: 16 bytes
  //   - hash function: SHA256
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& HmacSha256HalfSizeTag();

  // Returns a KeyTemplate that generates new instances of HmacKey
  // with the following parameters:
  //   - key size: 32 bytes
  //   - tag size: 32 bytes
  //   - hash function: SHA256
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& HmacSha256();

  // Returns a KeyTemplate that generates new instances of HmacKey
  // with the following parameters:
  //   - key size: 64 bytes
  //   - tag size: 32 bytes
  //   - hash function: SHA512
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& HmacSha512HalfSizeTag();

  // Returns a KeyTemplate that generates new instances of HmacKey
  // with the following parameters:
  //   - key size: 64 bytes
  //   - tag size: 64 bytes
  //   - hash function: SHA512
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& HmacSha512();

  // Returns a KeyTemplate that generates new instances of AesCmacKey
  // with the following parameters:
  //   - key size: 32 bytes
  //   - tag size: 16 bytes
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& AesCmac();
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_MAC_MAC_KEY_TEMPLATES_H_
