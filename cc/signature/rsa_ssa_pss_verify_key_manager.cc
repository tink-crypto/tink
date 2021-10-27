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

#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/bn_util.h"
#include "tink/public_key_verify.h"
#include "tink/subtle/rsa_ssa_pss_verify_boringssl.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/rsa_ssa_pss.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using crypto::tink::util::Enums;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::RsaSsaPssParams;
using google::crypto::tink::RsaSsaPssPublicKey;

StatusOr<std::unique_ptr<PublicKeyVerify>>
RsaSsaPssVerifyKeyManager::PublicKeyVerifyFactory::Create(
    const RsaSsaPssPublicKey& rsa_ssa_pss_public_key) const {
  subtle::SubtleUtilBoringSSL::RsaPublicKey rsa_pub_key;
  rsa_pub_key.n = rsa_ssa_pss_public_key.n();
  rsa_pub_key.e = rsa_ssa_pss_public_key.e();

  subtle::SubtleUtilBoringSSL::RsaSsaPssParams params;
  RsaSsaPssParams rsa_ssa_pss_params = rsa_ssa_pss_public_key.params();
  params.sig_hash = Enums::ProtoToSubtle(rsa_ssa_pss_params.sig_hash());
  params.mgf1_hash = Enums::ProtoToSubtle(rsa_ssa_pss_params.mgf1_hash());
  params.salt_length = rsa_ssa_pss_params.salt_length();

  auto rsa_ssa_pss_result =
      subtle::RsaSsaPssVerifyBoringSsl::New(rsa_pub_key, params);
  if (!rsa_ssa_pss_result.ok()) return rsa_ssa_pss_result.status();
  return {std::move(rsa_ssa_pss_result).ValueOrDie()};
}

Status RsaSsaPssVerifyKeyManager::ValidateKey(
    const RsaSsaPssPublicKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  auto status_or_n = internal::StringToBignum(key.n());
  if (!status_or_n.ok()) return status_or_n.status();
  auto modulus_status = subtle::SubtleUtilBoringSSL::ValidateRsaModulusSize(
      BN_num_bits(status_or_n.ValueOrDie().get()));
  if (!modulus_status.ok()) return modulus_status;
  auto exponent_status = subtle::SubtleUtilBoringSSL::ValidateRsaPublicExponent(
      key.e());
  if (!exponent_status.ok()) return exponent_status;
  return ValidateParams(key.params());
}

Status RsaSsaPssVerifyKeyManager::ValidateParams(
    const RsaSsaPssParams& params) const {
  auto hash_result = subtle::SubtleUtilBoringSSL::ValidateSignatureHash(
      Enums::ProtoToSubtle(params.sig_hash()));
  if (!hash_result.ok()) return hash_result;
  // The most common use case is that MGF1 hash is the same as signature hash.
  // This is recommended by RFC https://tools.ietf.org/html/rfc8017#section-8.1.
  // While using different hashes doesn't cause security vulnerabilities, there
  // is also no good reason to support different hashes. Furthermore:
  //
  //  - Golang does not support different hashes.
  //
  //  - BoringSSL supports different hashes just because of historical reason.
  // There is no real use case.
  //
  //  - Conscrypt/BouncyCastle do not support different hashes.
  if (params.mgf1_hash() != params.sig_hash()) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        absl::StrCat("MGF1 hash '",
                                     params.mgf1_hash(),
                                     "' is different from signature hash '",
                                     params.sig_hash(),
                                     "'"));
  }
  if (params.salt_length() < 0) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "salt length is negative");
  }
  return util::OkStatus();
}

}  // namespace tink
}  // namespace crypto
