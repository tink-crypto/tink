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

#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "google/protobuf/stubs/stringpiece.h"
#include "proto/common.pb.h"

namespace crypto {
namespace tink {

class EcUtil {
 public:
  // Computes and returns the ECDH shared secret, which is the x-coordinate of
  // the shared point, from a private key and a public key.
  // Returns an error if the public key is not a valid point on the private
  // key's curve.
  static util::StatusOr<std::string> ComputeEcdhSharedSecret(
      google::crypto::tink::EllipticCurveType curve_type,
      google::protobuf::StringPiece priv,
      google::protobuf::StringPiece pub_x,
      google::protobuf::StringPiece pub_y);

  // Returns the encoding size of a point on the specified elliptic curve
  // when the given 'point_format' is used.
  static util::StatusOr<uint32_t> EncodingSizeInBytes(
      google::crypto::tink::EllipticCurveType curve_type,
      google::crypto::tink::EcPointFormat point_format);

  // Returns the size (in bytes) of an element of the field over which
  // the curve is defined.
  static uint32_t FieldSizeInBytes(
      google::crypto::tink::EllipticCurveType curve_type);
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_EC_UTIL_H_
