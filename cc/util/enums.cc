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

namespace proto = google::crypto::tink;
namespace subtle = crypto::tink::subtle;

namespace crypto {
namespace tink {
namespace util {

// static
proto::EllipticCurveType Enums::SubtleToProto(subtle::EllipticCurveType type) {
  switch (type) {
  case subtle::EllipticCurveType::NIST_P224:
    return proto::EllipticCurveType::NIST_P224;
  case subtle::EllipticCurveType::NIST_P256:
    return proto::EllipticCurveType::NIST_P256;
  case subtle::EllipticCurveType::NIST_P384:
    return proto::EllipticCurveType::NIST_P384;
  case subtle::EllipticCurveType::NIST_P521:
    return proto::EllipticCurveType::NIST_P521;
  default:
    return proto::EllipticCurveType::UNKNOWN_CURVE;
  }
}

// static
subtle::EllipticCurveType Enums::ProtoToSubtle(proto::EllipticCurveType type) {
  switch (type) {
  case proto::EllipticCurveType::NIST_P224:
    return subtle::EllipticCurveType::NIST_P224;
  case proto::EllipticCurveType::NIST_P256:
    return subtle::EllipticCurveType::NIST_P256;
  case proto::EllipticCurveType::NIST_P384:
    return subtle::EllipticCurveType::NIST_P384;
  case proto::EllipticCurveType::NIST_P521:
    return subtle::EllipticCurveType::NIST_P521;
  default:
    return subtle::EllipticCurveType::UNKNOWN_CURVE;
  }
}

// static
proto::EcPointFormat Enums::SubtleToProto(subtle::EcPointFormat format) {
  switch (format) {
  case subtle::EcPointFormat::UNCOMPRESSED:
    return proto::EcPointFormat::UNCOMPRESSED;
  case subtle::EcPointFormat::COMPRESSED:
    return proto::EcPointFormat::COMPRESSED;
  default:
    return proto::EcPointFormat::UNKNOWN_FORMAT;
  }
}

// static
subtle::EcPointFormat Enums::ProtoToSubtle(proto::EcPointFormat format) {
  switch (format) {
  case proto::EcPointFormat::UNCOMPRESSED:
    return subtle::EcPointFormat::UNCOMPRESSED;
  case proto::EcPointFormat::COMPRESSED:
    return subtle::EcPointFormat::COMPRESSED;
  default:
    return subtle::EcPointFormat::UNKNOWN_FORMAT;
  }
}

// static
proto::HashType Enums::SubtleToProto(subtle::HashType type) {
  switch (type) {
  case subtle::HashType::SHA1:
    return proto::HashType::SHA1;
  case subtle::HashType::SHA224:
    return proto::HashType::SHA224;
  case subtle::HashType::SHA256:
    return proto::HashType::SHA256;
  case subtle::HashType::SHA512:
    return proto::HashType::SHA512;
  default:
    return proto::HashType::UNKNOWN_HASH;
  }
}

// static
subtle::HashType Enums::ProtoToSubtle(proto::HashType type) {
  switch (type) {
  case proto::HashType::SHA1:
    return subtle::HashType::SHA1;
  case proto::HashType::SHA224:
    return subtle::HashType::SHA224;
  case proto::HashType::SHA256:
    return subtle::HashType::SHA256;
  case proto::HashType::SHA512:
    return subtle::HashType::SHA512;
  default:
    return subtle::HashType::UNKNOWN_HASH;
  }
}

}  // namespace util
}  // namespace tink
}  // namespace crypto
