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

#include <utility>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/bn.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/md_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/public_key_verify.h"
#include "tink/subtle/rsa_ssa_pkcs1_verify_boringssl.h"
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
using google::crypto::tink::RsaSsaPkcs1Params;
using google::crypto::tink::RsaSsaPkcs1PublicKey;

util::StatusOr<std::unique_ptr<PublicKeyVerify>>
RsaSsaPkcs1VerifyKeyManager::PublicKeyVerifyFactory::Create(
    const RsaSsaPkcs1PublicKey& rsa_ssa_pkcs1_public_key) const {
  internal::RsaPublicKey rsa_pub_key;
  rsa_pub_key.n = rsa_ssa_pkcs1_public_key.n();
  rsa_pub_key.e = rsa_ssa_pkcs1_public_key.e();

  internal::RsaSsaPkcs1Params params;
  RsaSsaPkcs1Params rsa_ssa_pkcs1_params = rsa_ssa_pkcs1_public_key.params();
  params.hash_type = Enums::ProtoToSubtle(rsa_ssa_pkcs1_params.hash_type());

  auto rsa_ssa_pkcs1_result =
      subtle::RsaSsaPkcs1VerifyBoringSsl::New(rsa_pub_key, params);
  if (!rsa_ssa_pkcs1_result.ok()) return rsa_ssa_pkcs1_result.status();
  return {std::move(rsa_ssa_pkcs1_result.value())};
}

util::Status RsaSsaPkcs1VerifyKeyManager::ValidateParams(
    const RsaSsaPkcs1Params& params) const {
  return internal::IsHashTypeSafeForSignature(
      Enums::ProtoToSubtle(params.hash_type()));
}

util::Status RsaSsaPkcs1VerifyKeyManager::ValidateKey(
    const RsaSsaPkcs1PublicKey& key) const {
  util::Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> n =
      internal::StringToBignum(key.n());
  if (!n.ok()) {
    return n.status();
  }
  util::Status modulus_status =
      internal::ValidateRsaModulusSize(BN_num_bits(n->get()));
  if (!modulus_status.ok()) {
    return modulus_status;
  }
  util::Status exponent_status = internal::ValidateRsaPublicExponent(key.e());
  if (!exponent_status.ok()) {
    return exponent_status;
  }
  return ValidateParams(key.params());
}

}  // namespace tink
}  // namespace crypto
