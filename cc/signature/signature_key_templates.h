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

#ifndef TINK_SIGNATURE_SIGNATURE_KEY_TEMPLATES_H_
#define TINK_SIGNATURE_SIGNATURE_KEY_TEMPLATES_H_

#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// Pre-generated KeyTemplate for signature key types. One can use these
// templates to generate new KeysetHandle object with fresh keys.
// To generate a new keyset that contains a single EcdsaPrivateKey, one can do:
//   auto status = SignatureConfig::Init();
//   if (!status.ok()) { /* fail with error */ }
//   status = Config::Register(SignatureConfig::Tink_1_1_0());
//   if (!status.ok()) { /* fail with error */ }
//   auto handle_result =
//       KeysetHandle.GenerateNew(SignatureKeyTemplates.EcdsaP256());
//   if (!handle_result.ok()) { /* fail with error */ }
//   auto keyset_handle = std::move(handle_result.ValueOrDie());
class SignatureKeyTemplates {
 public:
  // Returns a KeyTemplate that generates new instances of EcdsaPrivateKey
  // with the following parameters:
  //   - EC curve: NIST P-256
  //   - hash function: SHA256
  //   - signature endocding: DER
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& EcdsaP256();

  // Returns a KeyTemplate that generates new instances of EcdsaPrivateKey
  // with the following parameters:
  //   - EC curve: NIST P-384
  //   - hash function: SHA512
  //   - signature endocding: DER
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& EcdsaP384();

  // Returns a KeyTemplate that generates new instances of EcdsaPrivateKey
  // with the following parameters:
  //   - EC curve: NIST P-521
  //   - hash function: SHA512
  //   - signature endocding: DER
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& EcdsaP521();
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_SIGNATURE_KEY_TEMPLATES_H_
