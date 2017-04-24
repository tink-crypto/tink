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

#ifndef TINK_SUBTLE_SUBTLE_UTIL_BORINGSSL_H_
#define TINK_SUBTLE_SUBTLE_UTIL_BORINGSSL_H_

#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "google/protobuf/stubs/stringpiece.h"
#include "openssl/evp.h"
#include "proto/common.pb.h"

using google::cloud::crypto::tink::HashType;
using google::cloud::crypto::tink::EllipticCurveType;
using google::cloud::crypto::tink::EcPointFormat;
using google::protobuf::StringPiece;
namespace cloud {
namespace crypto {
namespace tink {

class SubtleUtilBoringSSL {
 public:
  static util::StatusOr<EC_GROUP *> GetEcGroup(EllipticCurveType curve_type);

  static util::StatusOr<EC_POINT *> EcPointDecode(EllipticCurveType curve,
                                                  EcPointFormat format,
                                                  StringPiece encoded);
  static util::StatusOr<std::string> EcPointEncode(EllipticCurveType curve,
                                                   EcPointFormat format,
                                                   const EC_POINT *point);
  // Returns an EVP structure for a hash function.
  // The EVP_MD instances are sigletons owned by BoringSSL.
  static util::StatusOr<const EVP_MD *> EvpHash(HashType hash_type);
};

}  // namespace tink
}  // namespace crypto
}  // namespace cloud

#endif  // TINK_SUBTLE_SUBTLE_UTIL_BORINGSSL_H_
