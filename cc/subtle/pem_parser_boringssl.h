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
#ifndef TINK_SUBTLE_PEM_PARSER_BORINGSSL_H_
#define TINK_SUBTLE_PEM_PARSER_BORINGSSL_H_

#include "absl/strings/string_view.h"
#include "tink/internal/rsa_util.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

// Parses keys in in PEM format (RFC 7468).
// This is essentially a wrapper aroung BoringSSL APIs.
class PemParser {
 public:
  // Parses a given PEM serialized RSA public key `pem_serialized_key` into a
  // internal::RsaPublicKey.
  static util::StatusOr<std::unique_ptr<internal::RsaPublicKey>>
  ParseRsaPublicKey(absl::string_view pem_serialized_key);

  // Parses a given PEM serialized RSA private key `pem_serialized_key` into a
  // internal::RsaPublicKey.
  static util::StatusOr<std::unique_ptr<internal::RsaPrivateKey>>
  ParseRsaPrivateKey(absl::string_view pem_serialized_key);

  // Writes a given internal::RsaPublicKey `rsa_key` into a PEM
  // serialized RSA public key.
  static util::StatusOr<std::string> WriteRsaPublicKey(
      const internal::RsaPublicKey& rsa_public_key);

  // Writes a given internal::RsaPrivateKey `rsa_key` into a PEM
  // serialized RSA private key.
  static util::StatusOr<std::string> WriteRsaPrivateKey(
      const internal::RsaPrivateKey& rsa_private_key);

  // Parses a given PEM serialized EC public key `pem_serialized_key` into a
  // SubtleUtilBoringSSL::EcKey.
  static util::StatusOr<std::unique_ptr<SubtleUtilBoringSSL::EcKey>>
  ParseEcPublicKey(absl::string_view pem_serialized_key);

  // Parses a given PEM serialized EC private key `pem_serialized_key` into a
  // SubtleUtilBoringSSL::EcKey.
  static util::StatusOr<std::unique_ptr<SubtleUtilBoringSSL::EcKey>>
  ParseEcPrivateKey(absl::string_view pem_serialized_key);

  // Writes a given SubtleUtilBoringSSL::EcKey `ec_key` into a PEM serialized
  // EC public key.
  static util::StatusOr<std::string> WriteEcPublicKey(
      const SubtleUtilBoringSSL::EcKey& ec_key);

  // Writes a given SubtleUtilBoringSSL::EcKey `ec_key` into a PEM serialized
  // EC private key.
  static util::StatusOr<std::string> WriteEcPrivateKey(
      const SubtleUtilBoringSSL::EcKey& ec_key);
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto
#endif  // TINK_SUBTLE_PEM_PARSER_BORINGSSL_H_
