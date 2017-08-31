// Copyright 2017 Google Inc.
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

#include "cc/subtle/ecies_hkdf_sender_kem_boringssl.h"
#include "cc/subtle/hkdf.h"
#include "cc/subtle/subtle_util_boringssl.h"
#include "cc/util/ptr_util.h"
#include "openssl/bn.h"
#include "proto/common.pb.h"

using google::crypto::tink::EcPointFormat;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;
using google::protobuf::StringPiece;

namespace util = crypto::tink::util;

namespace crypto {
namespace tink {

EciesHkdfSenderKemBoringSsl::KemKey::KemKey(const std::string& kem_bytes,
                                            const std::string& symmetric_key)
    : kem_bytes_(kem_bytes), symmetric_key_(symmetric_key) {}

std::string EciesHkdfSenderKemBoringSsl::KemKey::KemKey::get_kem_bytes() {
  return kem_bytes_;
}

std::string EciesHkdfSenderKemBoringSsl::KemKey::KemKey::get_symmetric_key() {
  return symmetric_key_;
}

EciesHkdfSenderKemBoringSsl::EciesHkdfSenderKemBoringSsl(
EllipticCurveType curve, const std::string& pubx, const std::string& puby)
    : curve_(curve), pubx_(pubx), puby_(puby), peer_pub_key_(nullptr) {
}

// static
util::StatusOr<std::unique_ptr<EciesHkdfSenderKemBoringSsl>>
EciesHkdfSenderKemBoringSsl::New(
    EllipticCurveType curve, const std::string& pubx, const std::string& puby) {
  auto status_or_ec_point =
      SubtleUtilBoringSSL::GetEcPoint(curve, pubx, puby);
  if (!status_or_ec_point.ok()) return status_or_ec_point.status();
  auto sender_kem = util::wrap_unique(
      new EciesHkdfSenderKemBoringSsl(curve, pubx, puby));
  sender_kem->peer_pub_key_.reset(status_or_ec_point.ValueOrDie());
  return std::move(sender_kem);
}

util::StatusOr<std::unique_ptr<EciesHkdfSenderKemBoringSsl::KemKey>>
EciesHkdfSenderKemBoringSsl::GenerateKey(HashType hash, StringPiece hkdf_salt,
                                         StringPiece hkdf_info,
                                         uint32_t key_size_in_bytes,
                                         EcPointFormat point_format) const {
  if (peer_pub_key_.get() == nullptr) {
    return util::Status(util::error::INTERNAL,
                        "peer_pub_key_ wasn't initialized");
  }

  auto status_or_ec_group = SubtleUtilBoringSSL::GetEcGroup(curve_);
  if (!status_or_ec_group.ok()) {
    return status_or_ec_group.status();
  }
  bssl::UniquePtr<EC_GROUP> group(status_or_ec_group.ValueOrDie());
  bssl::UniquePtr<EC_KEY> ephemeral_key(EC_KEY_new());
  if (1 != EC_KEY_set_group(ephemeral_key.get(), group.get())) {
    return util::Status(util::error::INTERNAL, "EC_KEY_set_group failed");
  }
  if (1 != EC_KEY_generate_key(ephemeral_key.get())) {
    return util::Status(util::error::INTERNAL, "EC_KEY_generate_key failed");
  }
  const BIGNUM* ephemeral_priv = EC_KEY_get0_private_key(ephemeral_key.get());
  const EC_POINT* ephemeral_pub = EC_KEY_get0_public_key(ephemeral_key.get());
  auto status_or_string_kem =
      SubtleUtilBoringSSL::EcPointEncode(curve_, point_format, ephemeral_pub);
  if (!status_or_string_kem.ok()) {
    return status_or_string_kem.status();
  }
  std::string kem_bytes(status_or_string_kem.ValueOrDie());
  auto status_or_string_shared_secret =
      SubtleUtilBoringSSL::ComputeEcdhSharedSecret(curve_, ephemeral_priv,
                                                   peer_pub_key_.get());
  if (!status_or_string_shared_secret.ok()) {
    return status_or_string_shared_secret.status();
  }
  std::string shared_secret(status_or_string_shared_secret.ValueOrDie());
  auto status_or_string_symmetric_key = Hkdf::ComputeEciesHkdfSymmetricKey(
      hash, kem_bytes, shared_secret, hkdf_salt, hkdf_info, key_size_in_bytes);
  if (!status_or_string_symmetric_key.ok()) {
    return status_or_string_symmetric_key.status();
  }
  std::string symmetric_key(status_or_string_symmetric_key.ValueOrDie());
  auto kem_key = util::make_unique<KemKey>(kem_bytes, symmetric_key);
  return std::move(kem_key);
}

}  // namespace tink
}  // namespace crypto
