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

#include "tink/signature/rsa_ssa_pkcs1_verify_key_manager.h"

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
#include "proto/rsa_ssa_pkcs1.pb.h"

namespace crypto {
namespace tink {

using crypto::tink::util::Enums;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::RsaSsaPkcs1Params;
using google::crypto::tink::RsaSsaPkcs1PublicKey;

StatusOr<std::unique_ptr<PublicKeyVerify>>
RsaSsaPkcs1VerifyKeyManager::PublicKeyVerifyFactory::Create(
    const RsaSsaPkcs1PublicKey& rsa_ssa_pkcs1_public_key) const {
  subtle::SubtleUtilBoringSSL::RsaPublicKey rsa_pub_key;
  rsa_pub_key.n = rsa_ssa_pkcs1_public_key.n();
  rsa_pub_key.e = rsa_ssa_pkcs1_public_key.e();

  subtle::SubtleUtilBoringSSL::RsaSsaPkcs1Params params;
  RsaSsaPkcs1Params rsa_ssa_pkcs1_params = rsa_ssa_pkcs1_public_key.params();
  params.hash_type = Enums::ProtoToSubtle(rsa_ssa_pkcs1_params.hash_type());

  auto rsa_ssa_pkcs1_result =
      subtle::RsaSsaPkcs1VerifyBoringSsl::New(rsa_pub_key, params);
  if (!rsa_ssa_pkcs1_result.ok()) return rsa_ssa_pkcs1_result.status();
  return {std::move(rsa_ssa_pkcs1_result.ValueOrDie())};
}

Status RsaSsaPkcs1VerifyKeyManager::ValidateParams(
    const RsaSsaPkcs1Params& params) const {
  return subtle::SubtleUtilBoringSSL::ValidateSignatureHash(
      Enums::ProtoToSubtle(params.hash_type()));
}

Status RsaSsaPkcs1VerifyKeyManager::ValidateKey(
    const RsaSsaPkcs1PublicKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  auto status_or_n = subtle::SubtleUtilBoringSSL::str2bn(key.n());
  if (!status_or_n.ok()) return status_or_n.status();
  auto modulus_status = subtle::SubtleUtilBoringSSL::ValidateRsaModulusSize(
      BN_num_bits(status_or_n.ValueOrDie().get()));
  if (!modulus_status.ok()) return modulus_status;
  return ValidateParams(key.params());
}

}  // namespace tink
}  // namespace crypto
