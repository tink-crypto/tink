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

#include "tink/jwt/internal/raw_jwt_rsa_ssa_pss_sign_key_manager.h"

#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "tink/public_key_sign.h"
#include "tink/jwt/internal/raw_jwt_rsa_ssa_pss_verify_key_manager.h"
#include "tink/signature/sig_util.h"
#include "tink/subtle/rsa_ssa_pss_sign_boringssl.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/validation.h"
#include "proto/jwt_rsa_ssa_pss.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using crypto::tink::util::Enums;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::JwtRsaSsaPssAlgorithm;
using google::crypto::tink::JwtRsaSsaPssKeyFormat;
using google::crypto::tink::JwtRsaSsaPssPrivateKey;
using google::crypto::tink::HashType;

namespace {
std::unique_ptr<JwtRsaSsaPssPrivateKey> RsaPrivateKeySubtleToProto(
    const subtle::SubtleUtilBoringSSL::RsaPrivateKey& private_key) {
  auto key_proto = absl::make_unique<JwtRsaSsaPssPrivateKey>();
  key_proto->set_version(RawJwtRsaSsaPssSignKeyManager().get_version());
  key_proto->set_d(std::string(util::SecretDataAsStringView(private_key.d)));
  key_proto->set_p(std::string(util::SecretDataAsStringView(private_key.p)));
  key_proto->set_q(std::string(util::SecretDataAsStringView(private_key.q)));
  key_proto->set_dp(std::string(util::SecretDataAsStringView(private_key.dp)));
  key_proto->set_dq(std::string(util::SecretDataAsStringView(private_key.dq)));
  key_proto->set_crt(
      std::string(util::SecretDataAsStringView(private_key.crt)));
  auto* public_key_proto = key_proto->mutable_public_key();
  public_key_proto->set_version(RawJwtRsaSsaPssSignKeyManager().get_version());
  public_key_proto->set_n(private_key.n);
  public_key_proto->set_e(private_key.e);
  return key_proto;
}

subtle::SubtleUtilBoringSSL::RsaPrivateKey RsaPrivateKeyProtoToSubtle(
    const JwtRsaSsaPssPrivateKey& key_proto) {
  subtle::SubtleUtilBoringSSL::RsaPrivateKey key;
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

StatusOr<JwtRsaSsaPssPrivateKey> RawJwtRsaSsaPssSignKeyManager::CreateKey(
    const JwtRsaSsaPssKeyFormat& key_format) const {
  auto e = subtle::SubtleUtilBoringSSL::str2bn(
      key_format.public_exponent());
  if (!e.ok()) return e.status();

  subtle::SubtleUtilBoringSSL::RsaPrivateKey private_key;
  subtle::SubtleUtilBoringSSL::RsaPublicKey public_key;
  util::Status status = subtle::SubtleUtilBoringSSL::GetNewRsaKeyPair(
      key_format.modulus_size_in_bits(), e.ValueOrDie().get(),
      &private_key, &public_key);
  if (!status.ok()) return status;

  JwtRsaSsaPssPrivateKey key_proto =
      std::move(*RsaPrivateKeySubtleToProto(private_key));
  key_proto.mutable_public_key()->set_algorithm(key_format.algorithm());
  return key_proto;
}

StatusOr<std::unique_ptr<PublicKeySign>>
RawJwtRsaSsaPssSignKeyManager::PublicKeySignFactory::Create(
    const JwtRsaSsaPssPrivateKey& private_key) const {
  auto key = RsaPrivateKeyProtoToSubtle(private_key);
  JwtRsaSsaPssAlgorithm algorithm = private_key.public_key().algorithm();
  StatusOr<HashType> hash_or =
      RawJwtRsaSsaPssVerifyKeyManager::HashForPssAlgorithm(algorithm);
  if (!hash_or.ok()) {
    return hash_or.status();
  }
  StatusOr<int> salt_length_or =
      RawJwtRsaSsaPssVerifyKeyManager::SaltLengthForPssAlgorithm(algorithm);
  if (!salt_length_or.ok()) {
    return salt_length_or.status();
  }
  subtle::SubtleUtilBoringSSL::RsaSsaPssParams params;
  params.sig_hash = Enums::ProtoToSubtle(hash_or.ValueOrDie());
  params.mgf1_hash = Enums::ProtoToSubtle(hash_or.ValueOrDie());
  params.salt_length = salt_length_or.ValueOrDie();
  auto signer = subtle::RsaSsaPssSignBoringSsl::New(key, params);
  if (!signer.ok()) return signer.status();
  // To check that the key is correct, we sign a test message with private key
  // and verify with public key.
  auto verifier =
      RawJwtRsaSsaPssVerifyKeyManager().GetPrimitive<PublicKeyVerify>(
          private_key.public_key());
  if (!verifier.ok()) return verifier.status();
  auto sign_verify_result =
      SignAndVerify(signer.ValueOrDie().get(), verifier.ValueOrDie().get());
  if (!sign_verify_result.ok()) {
    return util::Status(util::error::INTERNAL,
                        "security bug: signing with private key followed by "
                        "verifying with public key failed");
  }
  return signer;
}

Status RawJwtRsaSsaPssSignKeyManager::ValidateKey(
    const JwtRsaSsaPssPrivateKey& key) const {
  Status status = ValidateVersion(key.version(), get_version());
  if (!status.ok()) return status;
  return RawJwtRsaSsaPssVerifyKeyManager().ValidateKey(key.public_key());
}

Status RawJwtRsaSsaPssSignKeyManager::ValidateKeyFormat(
    const JwtRsaSsaPssKeyFormat& key_format) const {
  auto modulus_status = subtle::SubtleUtilBoringSSL::ValidateRsaModulusSize(
      key_format.modulus_size_in_bits());
  if (!modulus_status.ok()) return modulus_status;
  auto exponent_status = subtle::SubtleUtilBoringSSL::ValidateRsaPublicExponent(
      key_format.public_exponent());
  if (!exponent_status.ok()) return exponent_status;
  return RawJwtRsaSsaPssVerifyKeyManager::ValidateAlgorithm(
      key_format.algorithm());
}

}  // namespace tink
}  // namespace crypto
