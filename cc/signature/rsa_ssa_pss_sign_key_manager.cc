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

#include "tink/signature/rsa_ssa_pss_sign_key_manager.h"

#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/public_key_sign.h"
#include "tink/signature/rsa_ssa_pss_verify_key_manager.h"
#include "tink/signature/sig_util.h"
#include "tink/subtle/rsa_ssa_pss_sign_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
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
using google::crypto::tink::RsaSsaPssKeyFormat;
using google::crypto::tink::RsaSsaPssParams;
using google::crypto::tink::RsaSsaPssPrivateKey;

namespace {
std::unique_ptr<RsaSsaPssPrivateKey> RsaPrivateKeySubtleToProto(
    const internal::RsaPrivateKey& private_key) {
  auto key_proto = absl::make_unique<RsaSsaPssPrivateKey>();
  key_proto->set_version(RsaSsaPssSignKeyManager().get_version());
  key_proto->set_d(std::string(util::SecretDataAsStringView(private_key.d)));
  key_proto->set_p(std::string(util::SecretDataAsStringView(private_key.p)));
  key_proto->set_q(std::string(util::SecretDataAsStringView(private_key.q)));
  key_proto->set_dp(std::string(util::SecretDataAsStringView(private_key.dp)));
  key_proto->set_dq(std::string(util::SecretDataAsStringView(private_key.dq)));
  key_proto->set_crt(
      std::string(util::SecretDataAsStringView(private_key.crt)));
  auto* public_key_proto = key_proto->mutable_public_key();
  public_key_proto->set_version(RsaSsaPssSignKeyManager().get_version());
  public_key_proto->set_n(private_key.n);
  public_key_proto->set_e(private_key.e);
  return key_proto;
}

internal::RsaPrivateKey RsaPrivateKeyProtoToSubtle(
    const RsaSsaPssPrivateKey& key_proto) {
  internal::RsaPrivateKey key;
  key.n = key_proto.public_key().n();
  key.e = key_proto.public_key().e();
  key.d = util::SecretDataFromStringView(key_proto.d());
  key.p = util::SecretDataFromStringView(key_proto.p());
  key.q = util::SecretDataFromStringView(key_proto.q());
  key.dp = util::SecretDataFromStringView(key_proto.dp());
  key.dq = util::SecretDataFromStringView(key_proto.dq());
  key.crt = util::SecretDataFromStringView(key_proto.crt());
  return key;
}

}  // namespace

StatusOr<RsaSsaPssPrivateKey> RsaSsaPssSignKeyManager::CreateKey(
    const RsaSsaPssKeyFormat& key_format) const {
  util::StatusOr<internal::SslUniquePtr<BIGNUM>> e =
      internal::StringToBignum(key_format.public_exponent());
  if (!e.ok()) {
    return e.status();
  }

  internal::RsaPrivateKey private_key;
  internal::RsaPublicKey public_key;
  util::Status status = internal::NewRsaKeyPair(
      key_format.modulus_size_in_bits(), e->get(), &private_key, &public_key);
  if (!status.ok()) {
    return status;
  }

  RsaSsaPssPrivateKey key_proto =
      std::move(*RsaPrivateKeySubtleToProto(private_key));
  *key_proto.mutable_public_key()->mutable_params() = key_format.params();
  return key_proto;
}

StatusOr<std::unique_ptr<PublicKeySign>>
RsaSsaPssSignKeyManager::PublicKeySignFactory::Create(
    const RsaSsaPssPrivateKey& private_key) const {
  auto key = RsaPrivateKeyProtoToSubtle(private_key);
  internal::RsaSsaPssParams params;
  const RsaSsaPssParams& params_proto = private_key.public_key().params();
  params.sig_hash = Enums::ProtoToSubtle(params_proto.sig_hash());
  params.mgf1_hash = Enums::ProtoToSubtle(params_proto.mgf1_hash());
  params.salt_length = params_proto.salt_length();
  auto signer = subtle::RsaSsaPssSignBoringSsl::New(key, params);
  if (!signer.ok()) return signer.status();
  // To check that the key is correct, we sign a test message with private key
  // and verify with public key.
  auto verifier = RsaSsaPssVerifyKeyManager().GetPrimitive<PublicKeyVerify>(
      private_key.public_key());
  if (!verifier.ok()) return verifier.status();
  auto sign_verify_result =
      SignAndVerify(signer.ValueOrDie().get(), verifier.ValueOrDie().get());
  if (!sign_verify_result.ok()) {
    return util::Status(absl::StatusCode::kInternal,
                        "security bug: signing with private key followed by "
                        "verifying with public key failed");
  }
  return signer;
}

Status RsaSsaPssSignKeyManager::ValidateKey(
    const RsaSsaPssPrivateKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  return RsaSsaPssVerifyKeyManager().ValidateKey(key.public_key());
}

Status RsaSsaPssSignKeyManager::ValidateKeyFormat(
    const RsaSsaPssKeyFormat& key_format) const {
  Status modulus_status =
      internal::ValidateRsaModulusSize(key_format.modulus_size_in_bits());
  if (!modulus_status.ok()) {
    return modulus_status;
  }
  Status exponent_status =
      internal::ValidateRsaPublicExponent(key_format.public_exponent());
  if (!exponent_status.ok()) {
    return exponent_status;
  }
  return RsaSsaPssVerifyKeyManager().ValidateParams(key_format.params());
}

}  // namespace tink
}  // namespace crypto
