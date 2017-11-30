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

#ifndef TINK_SUBTLE_EC_UTIL_H_
#define TINK_SUBTLE_EC_UTIL_H_

#include "absl/strings/string_view.h"
#include "cc/subtle/common_enums.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

class EcUtil {
 public:
  // Computes and returns the ECDH shared secret, which is the x-coordinate of
  // the shared point, from a private key and a public key.
  // Returns an error if the public key is not a valid point on the private
  // key's curve.
  static crypto::tink::util::StatusOr<std::string> ComputeEcdhSharedSecret(
      EllipticCurveType curve_type,
      absl::string_view priv,
      absl::string_view pub_x,
      absl::string_view pub_y);

  // Returns the encoding size of a point on the specified elliptic curve
  // when the given 'point_format' is used.
  static crypto::tink::util::StatusOr<uint32_t> EncodingSizeInBytes(
      EllipticCurveType curve_type, EcPointFormat point_format);

  // Returns the size (in bytes) of an element of the field over which
  // the curve is defined.
  static uint32_t FieldSizeInBytes(EllipticCurveType curve_type);
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_EC_UTIL_H_
