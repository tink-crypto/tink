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

#include "absl/base/macros.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// Pre-generated KeyTemplate for signature key types. One can use these
// templates to generate new KeysetHandle object with fresh keys.
// To generate a new keyset that contains a single EcdsaPrivateKey, one can do:
//
//   auto status = SignatureConfig::Register();
//   if (!status.ok()) { /* fail with error */ }
//   auto handle_result =
//       KeysetHandle::GenerateNew(SignatureKeyTemplates::EcdsaP256());
//   if (!handle_result.ok()) { /* fail with error */ }
//   auto keyset_handle = std::move(handle_result.value());
class SignatureKeyTemplates {
 public:
  // Returns a KeyTemplate that generates new instances of EcdsaPrivateKey
  // with the following parameters:
  //   - EC curve: NIST P-256
  //   - hash function: SHA256
  //   - signature encoding: DER
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& EcdsaP256();

  // Returns a KeyTemplate that generates new instances of EcdsaPrivateKey
  // with the following parameters:
  //   - EC curve: NIST P-384
  //   - hash function: SHA512
  //   - signature encoding: DER
  //   - OutputPrefixType: TINK
  ABSL_DEPRECATED("Use EcdsaP384Sha384() or EcdsaP384Sha512() instead")
  static const google::crypto::tink::KeyTemplate& EcdsaP384();

  // Returns a KeyTemplate that generates new instances of EcdsaPrivateKey
  // with the following parameters:
  //   - EC curve: NIST P-384
  //   - hash function: SHA384
  //   - signature encoding: DER
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& EcdsaP384Sha384();

  // Returns a KeyTemplate that generates new instances of EcdsaPrivateKey
  // with the following parameters:
  //   - EC curve: NIST P-384
  //   - hash function: SHA512
  //   - signature encoding: DER
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& EcdsaP384Sha512();

  // Returns a KeyTemplate that generates new instances of EcdsaPrivateKey
  // with the following parameters:
  //   - EC curve: NIST P-521
  //   - hash function: SHA512
  //   - signature encoding: DER
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& EcdsaP521();

  // Returns a KeyTemplate that generates new instances of EcdsaPrivateKey
  // with the following parameters:
  //   - EC curve: NIST P-256
  //   - hash function: SHA256
  //   - signature encoding: IEEE_P1363
  //   - OutputPrefixType: RAW
  // This template will give you compatibility with most other libraries.
  static const google::crypto::tink::KeyTemplate& EcdsaP256Raw();

  // Returns a KeyTemplate that generates new instances of EcdsaPrivateKey
  // with the following parameters:
  //   - EC curve: NIST P-256
  //   - hash function: SHA256
  //   - signature encoding: IEEE_P1363
  //   - OutputPrefixType: TINK
  // This key template does not make sense because IEEE P1363 mandates a raw
  // signature.
  ABSL_DEPRECATED("Use EcdsaP256() or EcdsaP256Raw() instead")
  static const google::crypto::tink::KeyTemplate& EcdsaP256Ieee();

  // Returns a KeyTemplate that generates new instances of EcdsaPrivateKey
  // with the following parameters:
  //   - EC curve: NIST P-384
  //   - hash function: SHA512
  //   - signature encoding: IEEE_P1363
  //   - OutputPrefixType: TINK
  // This key template does not make sense because IEEE P1363 mandates a raw
  // signature.
  ABSL_DEPRECATED(
      "Use EcdsaP384Sha384(), EcdsaP384Sha512() or EcdsaP256Raw() instead")
  static const google::crypto::tink::KeyTemplate& EcdsaP384Ieee();

  // Returns a KeyTemplate that generates new instances of EcdsaPrivateKey
  // with the following parameters:
  //   - EC curve: NIST P-521
  //   - hash function: SHA512
  //   - signature encoding: IEEE_P1363
  //   - OutputPrefixType: TINK
  // This key template does not make sense because IEEE P1363 mandates a raw
  // signature.
  ABSL_DEPRECATED("Use EcdsaP521() or EcdsaP256Raw() instead")
  static const google::crypto::tink::KeyTemplate& EcdsaP521Ieee();

  // Returns a KeyTemplate that generates new instances of RsaSsaPkcs1PrivateKey
  // with the following parameters:
  //   - Modulus size in bits: 3072.
  //   - Hash function: SHA256.
  //   - Public Exponent: 65537 (aka F4).
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& RsaSsaPkcs13072Sha256F4();

  // Returns a KeyTemplate that generates new instances of RsaSsaPkcs1PrivateKey
  // with the following parameters:
  //   - Modulus size in bits: 4096.
  //   - Hash function: SHA512.
  //   - Public Exponent: 65537 (aka F4).
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& RsaSsaPkcs14096Sha512F4();

  // Returns a KeyTemplate that generates new instances of RsaSsaPssPrivateKey
  // with the following parameters:
  //   - Modulus size in bits: 3072.
  //   - Signature hash: SHA256.
  //   - MGF1 hash: SHA256.
  //   - Salt length: 32 (i.e., SHA256's output length).
  //   - Public Exponent: 65537 (aka F4).
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& RsaSsaPss3072Sha256Sha256F4();

  // Returns a KeyTemplate that generates new instances of RsaSsaPssPrivateKey
  // with the following parameters:
  //   - Modulus size in bits: 4096.
  //   - Signature hash: SHA512.
  //   - MGF1 hash: SHA512.
  //   - Salt length: 64 (i.e., SHA512's output length).
  //   - Public Exponent: 65537 (aka F4).
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& RsaSsaPss4096Sha512Sha512F4();

  // Returns a KeyTemplate that generates new instances of RsaSsaPssPrivateKey
  // with the following parameters:
  //   - Modulus size in bits: 4096.
  //   - Signature hash: SHA384.
  //   - MGF1 hash: SHA384.
  //   - Salt length: 48 (i.e., SHA384's output length).
  //   - Public Exponent: 65537 (aka F4).
  //   - OutputPrefixType: TINK
  static const google::crypto::tink::KeyTemplate& RsaSsaPss4096Sha384Sha384F4();

  // Returns a KeyTemplate that generates new instances of Ed25519PrivateKey.
  static const google::crypto::tink::KeyTemplate& Ed25519();

  // Returns a KeyTemplate that generates new instances of Ed25519PrivateKey.
  // The difference between Ed25519WithRawOutput and Ed25519 is the format of
  // signatures generated. Ed25519WithRawOutput generates signatures of
  // OutputPrefixType::RAW format, which is 64 bytes long.
  static const google::crypto::tink::KeyTemplate& Ed25519WithRawOutput();
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SIGNATURE_SIGNATURE_KEY_TEMPLATES_H_
