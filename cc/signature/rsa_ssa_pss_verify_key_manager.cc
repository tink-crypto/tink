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

#include "absl/strings/string_view.h"
#include "tink/key_manager.h"
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

// TODO(quannguyen):
//  + Validate mgf1 hash, salt length and possible e.
//  + Add friend class RsaSsaPssSignBoringSSL.
namespace crypto {
namespace tink {

using crypto::tink::util::Enums;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyData;
using google::crypto::tink::RsaSsaPssKeyFormat;
using google::crypto::tink::RsaSsaPssParams;
using google::crypto::tink::RsaSsaPssPublicKey;
using portable_proto::MessageLite;

class RsaSsaPssPublicKeyFactory : public KeyFactory {
 public:
  RsaSsaPssPublicKeyFactory() {}

  // Not implemented for public keys.
  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(const portable_proto::MessageLite& key_format) const override;

  // Not implemented for public keys.
  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(absl::string_view serialized_key_format) const override;

  // Not implemented for public keys.
  crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  NewKeyData(absl::string_view serialized_key_format) const override;
};

StatusOr<std::unique_ptr<MessageLite>> RsaSsaPssPublicKeyFactory::NewKey(
    const portable_proto::MessageLite& key_format) const {
  return util::Status(util::error::UNIMPLEMENTED,
                      "Operation not supported for public keys, "
                      "please use the RsaSsaPssSignKeyManager.");
}

StatusOr<std::unique_ptr<MessageLite>> RsaSsaPssPublicKeyFactory::NewKey(
    absl::string_view serialized_key_format) const {
  return util::Status(util::error::UNIMPLEMENTED,
                      "Operation not supported for public keys, "
                      "please use the RsaSsaPssSignKeyManager.");
}

StatusOr<std::unique_ptr<KeyData>> RsaSsaPssPublicKeyFactory::NewKeyData(
    absl::string_view serialized_key_format) const {
  return util::Status(util::error::UNIMPLEMENTED,
                      "Operation not supported for public keys, "
                      "please use the RsaSsaPssSignKeyManager.");
}

constexpr char RsaSsaPssVerifyKeyManager::kKeyTypePrefix[];
constexpr char RsaSsaPssVerifyKeyManager::kKeyType[];
constexpr uint32_t RsaSsaPssVerifyKeyManager::kVersion;

RsaSsaPssVerifyKeyManager::RsaSsaPssVerifyKeyManager()
    : key_type_(kKeyType), key_factory_(new RsaSsaPssPublicKeyFactory()) {}

const std::string& RsaSsaPssVerifyKeyManager::get_key_type() const {
  return key_type_;
}

const KeyFactory& RsaSsaPssVerifyKeyManager::get_key_factory() const {
  return *key_factory_;
}

uint32_t RsaSsaPssVerifyKeyManager::get_version() const { return kVersion; }

StatusOr<std::unique_ptr<PublicKeyVerify>>
RsaSsaPssVerifyKeyManager::GetPrimitive(const KeyData& key_data) const {
  if (DoesSupport(key_data.type_url())) {
    RsaSsaPssPublicKey rsa_ssa_pss_public_key;
    if (!rsa_ssa_pss_public_key.ParseFromString(key_data.value())) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Could not parse key_data.value as key type '%s'.",
                       key_data.type_url().c_str());
    }
    return GetPrimitiveImpl(rsa_ssa_pss_public_key);
  } else {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key type '%s' is not supported by this manager.",
                     key_data.type_url().c_str());
  }
}

StatusOr<std::unique_ptr<PublicKeyVerify>>
RsaSsaPssVerifyKeyManager::GetPrimitive(const MessageLite& key) const {
  std::string key_type = std::string(kKeyTypePrefix) + key.GetTypeName();
  if (DoesSupport(key_type)) {
    const RsaSsaPssPublicKey& rsa_ssa_pss_public_key =
        static_cast<const RsaSsaPssPublicKey&>(key);
    return GetPrimitiveImpl(rsa_ssa_pss_public_key);
  } else {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Key type '%s' is not supported by this manager.",
                     key_type.c_str());
  }
}

StatusOr<std::unique_ptr<PublicKeyVerify>>
RsaSsaPssVerifyKeyManager::GetPrimitiveImpl(
    const RsaSsaPssPublicKey& rsa_ssa_pss_public_key) const {
  Status status = Validate(rsa_ssa_pss_public_key);
  if (!status.ok()) return status;
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
  std::unique_ptr<PublicKeyVerify> rsa_ssa_pss(
      rsa_ssa_pss_result.ValueOrDie().release());
  return std::move(rsa_ssa_pss);
}

// static
Status RsaSsaPssVerifyKeyManager::Validate(const RsaSsaPssParams& params) {
  // Validates signature hash.
  switch (params.sig_hash()) {
    case HashType::SHA256: /* fall through */
    case HashType::SHA512:
      break;
    case HashType::SHA1:
      return util::Status(util::error::INVALID_ARGUMENT,
                          "SHA1 is not safe for digital signature");
    default:
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Unsupported hash function '%d'", params.sig_hash());
  }
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
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "MGF1 hash '%d' is different from signature hash '%d'",
                     params.mgf1_hash(), params.sig_hash());
  }
  return Status::OK;
}

// static
Status RsaSsaPssVerifyKeyManager::Validate(const RsaSsaPssPublicKey& key) {
  Status status = ValidateVersion(key.version(), kVersion);
  if (!status.ok()) return status;
  auto status_or_n = subtle::SubtleUtilBoringSSL::str2bn(key.n());
  if (!status_or_n.ok()) return status_or_n.status();
  size_t modulus_size = BN_num_bits(status_or_n.ValueOrDie().get());
  if (modulus_size < kMinModulusSizeInBits) {
    return ToStatusF(
        util::error::INVALID_ARGUMENT,
        "Modulus size is %zu; only modulus size >= 2048-bit is supported",
        modulus_size);
  }
  return Validate(key.params());
}

// static
Status RsaSsaPssVerifyKeyManager::Validate(
    const RsaSsaPssKeyFormat& key_format) {
  size_t modulus_size = key_format.modulus_size_in_bits();
  if (modulus_size < kMinModulusSizeInBits) {
    return ToStatusF(
        util::error::INTERNAL,
        "Modulus size is %zu; only modulus size >= 2048-bit is supported",
        modulus_size);
  }
  return Validate(key_format.params());
}

}  // namespace tink
}  // namespace crypto
