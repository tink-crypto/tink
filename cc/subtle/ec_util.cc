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
  bssl::UniquePtr<EC_POINT> shared_point(EC_POINT_new(priv_group.get()));
  // BoringSSL's EC_POINT_set_affine_coordinates_GFp documentation says that
  // "unlike with OpenSSL, it's considered an error if the point is not on the
  // curve". To be sure, we make this security critical check.
  if (1 != EC_POINT_is_on_curve(priv_group.get(), pub_key.get(), nullptr)) {
    return util::Status(util::error::INTERNAL, "Point is not on curve");
  }
  // Compute the shared point.
  if (1 != EC_POINT_mul(priv_group.get(), shared_point.get(), nullptr,
                        pub_key.get(), priv_key.get(), nullptr)) {
    return util::Status(util::error::INTERNAL, "Point multiplication failed");
  }
  // Check for buggy computation.
  if (1 !=
      EC_POINT_is_on_curve(priv_group.get(), shared_point.get(), nullptr)) {
    return util::Status(util::error::INTERNAL, "Shared point is not on curve");
  }
  bssl::UniquePtr<BIGNUM> shared_x(BN_new());
  bssl::UniquePtr<BIGNUM> shared_y(BN_new());
  if (1 != EC_POINT_get_affine_coordinates_GFp(
               priv_group.get(), shared_point.get(), shared_x.get(),
               shared_y.get(), nullptr)) {
    return util::Status(util::error::INTERNAL,
                        "EC_POINT_get_affine_coordinates_GFp failed");
  }

  // Get shared point's x coordinate.
  unsigned curve_size_in_bits = EC_GROUP_get_degree(priv_group.get());
  unsigned curve_size_in_bytes = (curve_size_in_bits + 7) / 8;
  size_t x_size_in_bytes = BN_num_bytes(shared_x.get());
  std::unique_ptr<uint8_t> shared_secret_bytes(
      new uint8_t[curve_size_in_bytes]);
  memset(shared_secret_bytes.get(), 0, curve_size_in_bytes);
  if (curve_size_in_bytes < x_size_in_bytes) {
    return util::Status(util::error::INTERNAL,
                        "The x-coordinate of the shared point is larger than "
                        "the size of the curve");
  }
  int zeros = int(curve_size_in_bytes - x_size_in_bytes);
  int written = BN_bn2bin(shared_x.get(), &shared_secret_bytes.get()[zeros]);
  if (written != int(x_size_in_bytes)) {
    return util::Status(util::error::INTERNAL, "BN_bn_2bin failed");
  }
  return std::string(reinterpret_cast<char *>(shared_secret_bytes.get()),
                     curve_size_in_bytes);
}

}  // namespace tink
}  // namespace crypto
}  // namespace cloud
