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

#include "cc/subtle/ec_util.h"
#include <memory>
#include <string>
#include "cc/subtle/subtle_util_boringssl.h"
#include "openssl/bn.h"
#include "openssl/ec.h"
#include "openssl/x509.h"

namespace cloud {
namespace crypto {
namespace tink {

// static
util::StatusOr<std::string> EcUtil::ComputeEcdhSharedSecret(
    EllipticCurveType curve, StringPiece priv, StringPiece pubx,
    StringPiece puby) {
  bssl::UniquePtr<BIGNUM> priv_key(
      BN_bin2bn(reinterpret_cast<const unsigned char *>(priv.data()),
                priv.size(), nullptr));
  bssl::UniquePtr<BIGNUM> bn_x(
      BN_bin2bn(reinterpret_cast<const unsigned char *>(pubx.data()),
                pubx.size(), nullptr));
  bssl::UniquePtr<BIGNUM> bn_y(
      BN_bin2bn(reinterpret_cast<const unsigned char *>(puby.data()),
                puby.length(), nullptr));
  if (priv_key.get() == nullptr || bn_x.get() == nullptr ||
      bn_y.get() == nullptr) {
    return util::Status(util::error::INTERNAL, "BN_bin2bn failed");
  }
  auto status_or_ec_group = SubtleUtilBoringSSL::GetEcGroup(curve);
  if (!status_or_ec_group.ok()) {
    return status_or_ec_group.status();
  }
  bssl::UniquePtr<EC_GROUP> priv_group(status_or_ec_group.ValueOrDie());
  bssl::UniquePtr<EC_POINT> pub_key(EC_POINT_new(priv_group.get()));
  if (1 != EC_POINT_set_affine_coordinates_GFp(priv_group.get(), pub_key.get(),
                                               bn_x.get(), bn_y.get(),
                                               nullptr)) {
    return util::Status(util::error::INTERNAL,
                        "EC_POINT_set_affine_coordinates_GFp failed");
  }
  return SubtleUtilBoringSSL::ComputeEcdhSharedSecret(curve, priv_key.get(),
                                                      pub_key.get());
}

}  // namespace tink
}  // namespace crypto
}  // namespace cloud
