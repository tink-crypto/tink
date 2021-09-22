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

#include "tink/jwt/internal/raw_jwt_rsa_ssa_pkcs1_verify_key_manager.h"

#include <utility>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/public_key_verify.h"
#include "tink/subtle/rsa_ssa_pkcs1_verify_boringssl.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/jwt_rsa_ssa_pkcs1.pb.h"

namespace crypto {
namespace tink {

using crypto::tink::util::Enums;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::HashType;
using google::crypto::tink::JwtRsaSsaPkcs1Algorithm;
using google::crypto::tink::JwtRsaSsaPkcs1PublicKey;

StatusOr<std::unique_ptr<PublicKeyVerify>>
RawJwtRsaSsaPkcs1VerifyKeyManager::PublicKeyVerifyFactory::Create(
    const JwtRsaSsaPkcs1PublicKey& jwt_rsa_ssa_pkcs1_public_key) const {
  subtle::SubtleUtilBoringSSL::RsaPublicKey rsa_pub_key;
  rsa_pub_key.n = jwt_rsa_ssa_pkcs1_public_key.n();
  rsa_pub_key.e = jwt_rsa_ssa_pkcs1_public_key.e();

  util::StatusOr<google::crypto::tink::HashType> hash =
      RawJwtRsaSsaPkcs1VerifyKeyManager::HashForPkcs1Algorithm(
          jwt_rsa_ssa_pkcs1_public_key.algorithm());
  if (!hash.ok()) {
    return hash.status();
  }
  subtle::SubtleUtilBoringSSL::RsaSsaPkcs1Params params;
  params.hash_type = Enums::ProtoToSubtle(*hash);

  util::StatusOr<std::unique_ptr<subtle::RsaSsaPkcs1VerifyBoringSsl>> verify =
      subtle::RsaSsaPkcs1VerifyBoringSsl::New(rsa_pub_key, params);
  if (!verify.ok()) return verify.status();
  return {std::move(*verify)};
}

Status RawJwtRsaSsaPkcs1VerifyKeyManager::ValidateKey(
    const JwtRsaSsaPkcs1PublicKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  util::StatusOr<bssl::UniquePtr<BIGNUM>> n =
      subtle::SubtleUtilBoringSSL::str2bn(key.n());
  if (!n.ok()) return n.status();
  util::Status modulus_status =
      subtle::SubtleUtilBoringSSL::ValidateRsaModulusSize(
          BN_num_bits(n->get()));
  if (!modulus_status.ok()) return modulus_status;
  util::Status exponent_status =
      subtle::SubtleUtilBoringSSL::ValidateRsaPublicExponent(key.e());
  if (!exponent_status.ok()) return exponent_status;
  return ValidateAlgorithm(key.algorithm());
}

Status RawJwtRsaSsaPkcs1VerifyKeyManager::ValidateAlgorithm(
    const JwtRsaSsaPkcs1Algorithm& algorithm) {
  switch (algorithm) {
    case JwtRsaSsaPkcs1Algorithm::RS256:
    case JwtRsaSsaPkcs1Algorithm::RS384:
    case JwtRsaSsaPkcs1Algorithm::RS512:
      return util::OkStatus();
    default:
      return Status(util::error::INVALID_ARGUMENT,
                    "Unsupported RSA SSA PKCS1 Algorithm");
  }
  return util::OkStatus();
}

StatusOr<HashType> RawJwtRsaSsaPkcs1VerifyKeyManager::HashForPkcs1Algorithm(
    const JwtRsaSsaPkcs1Algorithm& algorithm) {
  switch (algorithm) {
    case JwtRsaSsaPkcs1Algorithm::RS256:
      return HashType::SHA256;
    case JwtRsaSsaPkcs1Algorithm::RS384:
      return HashType::SHA384;
    case JwtRsaSsaPkcs1Algorithm::RS512:
      return HashType::SHA512;
    default:
      return Status(util::error::INVALID_ARGUMENT,
                    "Unsupported RSA SSA PKCS1 Algorithm");
  }
}

}  // namespace tink
}  // namespace crypto
