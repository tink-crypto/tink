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

#include "tink/jwt/internal/raw_jwt_rsa_ssa_pss_verify_key_manager.h"

#include <utility>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/public_key_verify.h"
#include "tink/subtle/rsa_ssa_pss_verify_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/jwt_rsa_ssa_pss.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using ::crypto::tink::subtle::RsaSsaPssVerifyBoringSsl;
using ::crypto::tink::util::Enums;
using ::crypto::tink::util::Status;
using ::crypto::tink::util::StatusOr;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::JwtRsaSsaPssAlgorithm;
using ::google::crypto::tink::JwtRsaSsaPssPublicKey;

StatusOr<std::unique_ptr<PublicKeyVerify>>
RawJwtRsaSsaPssVerifyKeyManager::PublicKeyVerifyFactory::Create(
    const JwtRsaSsaPssPublicKey& rsa_ssa_pss_public_key) const {
  internal::RsaPublicKey rsa_pub_key;
  rsa_pub_key.n = rsa_ssa_pss_public_key.n();
  rsa_pub_key.e = rsa_ssa_pss_public_key.e();
  JwtRsaSsaPssAlgorithm algorithm = rsa_ssa_pss_public_key.algorithm();
  StatusOr<HashType> hash_or = HashForPssAlgorithm(algorithm);
  if (!hash_or.ok()) {
    return hash_or.status();
  }
  StatusOr<int> salt_length = SaltLengthForPssAlgorithm(algorithm);
  if (!salt_length.ok()) {
    return salt_length.status();
  }
  internal::RsaSsaPssParams params;
  params.sig_hash = Enums::ProtoToSubtle(hash_or.value());
  params.mgf1_hash = Enums::ProtoToSubtle(hash_or.value());
  params.salt_length = *salt_length;

  util::StatusOr<std::unique_ptr<RsaSsaPssVerifyBoringSsl>> verify =
      subtle::RsaSsaPssVerifyBoringSsl::New(rsa_pub_key, params);
  if (!verify.ok()) {
    return verify.status();
  }
  return {*std::move(verify)};
}

Status RawJwtRsaSsaPssVerifyKeyManager::ValidateKey(
    const JwtRsaSsaPssPublicKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) {
    return status;
  }
  StatusOr<internal::SslUniquePtr<BIGNUM>> n =
      internal::StringToBignum(key.n());
  if (!n.ok()) {
    return n.status();
  }
  Status modulus_status =
      internal::ValidateRsaModulusSize(BN_num_bits(n->get()));
  if (!modulus_status.ok()) {
    return modulus_status;
  }
  Status exponent_status = internal::ValidateRsaPublicExponent(key.e());
  if (!exponent_status.ok()) {
    return exponent_status;
  }
  return ValidateAlgorithm(key.algorithm());
}

Status RawJwtRsaSsaPssVerifyKeyManager::ValidateAlgorithm(
    const JwtRsaSsaPssAlgorithm& algorithm) {
  switch (algorithm) {
    case JwtRsaSsaPssAlgorithm::PS256:
    case JwtRsaSsaPssAlgorithm::PS384:
    case JwtRsaSsaPssAlgorithm::PS512:
      return util::OkStatus();
    default:
      return Status(absl::StatusCode::kInvalidArgument,
                    "Unsupported RSA SSA PSS Algorithm");
  }
  return util::OkStatus();
}

StatusOr<HashType> RawJwtRsaSsaPssVerifyKeyManager::HashForPssAlgorithm(
    const JwtRsaSsaPssAlgorithm& algorithm) {
  switch (algorithm) {
    case JwtRsaSsaPssAlgorithm::PS256:
      return HashType::SHA256;
    case JwtRsaSsaPssAlgorithm::PS384:
      return HashType::SHA384;
    case JwtRsaSsaPssAlgorithm::PS512:
      return HashType::SHA512;
    default:
      return Status(absl::StatusCode::kInvalidArgument,
                    "Unsupported RSA SSA PSS Algorithm");
  }
}

StatusOr<int> RawJwtRsaSsaPssVerifyKeyManager::SaltLengthForPssAlgorithm(
    const JwtRsaSsaPssAlgorithm& algorithm) {
  switch (algorithm) {
    case JwtRsaSsaPssAlgorithm::PS256:
      return 32;
    case JwtRsaSsaPssAlgorithm::PS384:
      return 48;
    case JwtRsaSsaPssAlgorithm::PS512:
      return 64;
    default:
      return Status(absl::StatusCode::kInvalidArgument,
                    "Unsupported RSA SSA PSS Algorithm");
  }
}

}  // namespace tink
}  // namespace crypto
