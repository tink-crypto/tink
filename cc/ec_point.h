// Copyright 2024 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_EC_POINT_H_
#define TINK_EC_POINT_H_

#include "tink/big_integer.h"

namespace crypto {
namespace tink {

class EcPoint {
 public:
  EcPoint(const BigInteger& x, const BigInteger& y) : x_(x), y_(y) {}

  // Returns affine x-coordinate.
  const BigInteger& GetX() const { return x_; }
  // Returns affine y-coordinate.
  const BigInteger& GetY() const { return y_; }

  bool operator==(const EcPoint& other) const {
    return x_ == other.x_ && y_ == other.y_;
  }

  bool operator!=(const EcPoint& other) const { return !(*this == other); }

 private:
  // Affine coordinates.
  BigInteger x_;
  BigInteger y_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_EC_POINT_H_
