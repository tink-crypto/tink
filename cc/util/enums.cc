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

#include "cc/util/enums.h"
#include "proto/common.pb.h"

namespace pb = google::crypto::tink;

namespace crypto {
namespace tink {
namespace util {

// static
pb::EllipticCurveType Enums::SubtleToProto(subtle::EllipticCurveType type) {
  switch (type) {
  case subtle::EllipticCurveType::NIST_P224:
    return pb::EllipticCurveType::NIST_P224;
  case subtle::EllipticCurveType::NIST_P256:
    return pb::EllipticCurveType::NIST_P256;
  case subtle::EllipticCurveType::NIST_P384:
    return pb::EllipticCurveType::NIST_P384;
  case subtle::EllipticCurveType::NIST_P521:
    return pb::EllipticCurveType::NIST_P521;
  default:
    return pb::EllipticCurveType::UNKNOWN_CURVE;
  }
}

// static
subtle::EllipticCurveType Enums::ProtoToSubtle(pb::EllipticCurveType type) {
  switch (type) {
  case pb::EllipticCurveType::NIST_P224:
    return subtle::EllipticCurveType::NIST_P224;
  case pb::EllipticCurveType::NIST_P256:
    return subtle::EllipticCurveType::NIST_P256;
  case pb::EllipticCurveType::NIST_P384:
    return subtle::EllipticCurveType::NIST_P384;
  case pb::EllipticCurveType::NIST_P521:
    return subtle::EllipticCurveType::NIST_P521;
  default:
    return subtle::EllipticCurveType::UNKNOWN_CURVE;
  }
}

// static
pb::EcPointFormat Enums::SubtleToProto(subtle::EcPointFormat format) {
  switch (format) {
  case subtle::EcPointFormat::UNCOMPRESSED:
    return pb::EcPointFormat::UNCOMPRESSED;
  case subtle::EcPointFormat::COMPRESSED:
    return pb::EcPointFormat::COMPRESSED;
  default:
    return pb::EcPointFormat::UNKNOWN_FORMAT;
  }
}

// static
subtle::EcPointFormat Enums::ProtoToSubtle(pb::EcPointFormat format) {
  switch (format) {
  case pb::EcPointFormat::UNCOMPRESSED:
    return subtle::EcPointFormat::UNCOMPRESSED;
  case pb::EcPointFormat::COMPRESSED:
    return subtle::EcPointFormat::COMPRESSED;
  default:
    return subtle::EcPointFormat::UNKNOWN_FORMAT;
  }
}

// static
pb::HashType Enums::SubtleToProto(subtle::HashType type) {
  switch (type) {
  case subtle::HashType::SHA1:
    return pb::HashType::SHA1;
  case subtle::HashType::SHA224:
    return pb::HashType::SHA224;
  case subtle::HashType::SHA256:
    return pb::HashType::SHA256;
  case subtle::HashType::SHA512:
    return pb::HashType::SHA512;
  default:
    return pb::HashType::UNKNOWN_HASH;
  }
}

// static
subtle::HashType Enums::ProtoToSubtle(pb::HashType type) {
  switch (type) {
  case pb::HashType::SHA1:
    return subtle::HashType::SHA1;
  case pb::HashType::SHA224:
    return subtle::HashType::SHA224;
  case pb::HashType::SHA256:
    return subtle::HashType::SHA256;
  case pb::HashType::SHA512:
    return subtle::HashType::SHA512;
  default:
    return subtle::HashType::UNKNOWN_HASH;
  }
}

}  // namespace util
}  // namespace tink
}  // namespace crypto
