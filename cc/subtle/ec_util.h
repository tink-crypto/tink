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

#include "absl/base/macros.h"
#include "tink/internal/ec_util.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace subtle {

class EcUtil {
 public:
  // Returns the encoding size of a point on the specified elliptic curve
  // when the given 'point_format' is used.
  ABSL_DEPRECATE_AND_INLINE()
  static inline crypto::tink::util::StatusOr<uint32_t> EncodingSizeInBytes(
      EllipticCurveType curve_type, EcPointFormat point_format) {
    return internal::EcPointEncodingSizeInBytes(curve_type, point_format);
  }

  // Returns the size (in bytes) of an element of the field over which
  // the curve is defined.
  ABSL_DEPRECATE_AND_INLINE()
  static inline uint32_t FieldSizeInBytes(EllipticCurveType curve_type) {
    util::StatusOr<int32_t> size = internal::EcFieldSizeInBytes(curve_type);
    if (!size.ok()) {
      return 0;
    }
    return *size;
  }
};

}  // namespace subtle
}  // namespace tink
}  // namespace crypto

#endif  // TINK_SUBTLE_EC_UTIL_H_
