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

#include "tink/util/enums.h"

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "proto/common.pb.h"
#include "proto/ecdsa.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace util {

namespace pb = google::crypto::tink;

// static
pb::EllipticCurveType Enums::SubtleToProto(subtle::EllipticCurveType type) {
  switch (type) {
    case subtle::EllipticCurveType::NIST_P256:
      return pb::EllipticCurveType::NIST_P256;
    case subtle::EllipticCurveType::NIST_P384:
      return pb::EllipticCurveType::NIST_P384;
    case subtle::EllipticCurveType::NIST_P521:
      return pb::EllipticCurveType::NIST_P521;
    case subtle::EllipticCurveType::CURVE25519:
      return pb::EllipticCurveType::CURVE25519;
    default:
      return pb::EllipticCurveType::UNKNOWN_CURVE;
  }
}

// static
subtle::EllipticCurveType Enums::ProtoToSubtle(pb::EllipticCurveType type) {
  switch (type) {
    case pb::EllipticCurveType::NIST_P256:
      return subtle::EllipticCurveType::NIST_P256;
    case pb::EllipticCurveType::NIST_P384:
      return subtle::EllipticCurveType::NIST_P384;
    case pb::EllipticCurveType::NIST_P521:
      return subtle::EllipticCurveType::NIST_P521;
    case pb::EllipticCurveType::CURVE25519:
      return subtle::EllipticCurveType::CURVE25519;
    default:
      return subtle::EllipticCurveType::UNKNOWN_CURVE;
  }
}

// static
pb::EcPointFormat Enums::SubtleToProto(subtle::EcPointFormat format) {
  switch (format) {
    case subtle::EcPointFormat::UNCOMPRESSED:
      return pb::EcPointFormat::UNCOMPRESSED;
    case subtle::EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED:
      return pb::EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED;
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
    case pb::EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED:
      return subtle::EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED;
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
    case subtle::HashType::SHA384:
      return pb::HashType::SHA384;
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
    case pb::HashType::SHA384:
      return subtle::HashType::SHA384;
    case pb::HashType::SHA512:
      return subtle::HashType::SHA512;
    default:
      return subtle::HashType::UNKNOWN_HASH;
  }
}

// static
subtle::EcdsaSignatureEncoding Enums::ProtoToSubtle(
    pb::EcdsaSignatureEncoding encoding) {
  switch (encoding) {
    case pb::EcdsaSignatureEncoding::DER:
      return subtle::EcdsaSignatureEncoding::DER;
    case pb::EcdsaSignatureEncoding::IEEE_P1363:
      return subtle::EcdsaSignatureEncoding::IEEE_P1363;
    default:
      return subtle::EcdsaSignatureEncoding::UNKNOWN_ENCODING;
  }
}

// static
pb::EcdsaSignatureEncoding Enums::SubtleToProto(
    subtle::EcdsaSignatureEncoding encoding) {
  switch (encoding) {
    case subtle::EcdsaSignatureEncoding::DER:
      return pb::EcdsaSignatureEncoding::DER;
    case subtle::EcdsaSignatureEncoding::IEEE_P1363:
      return pb::EcdsaSignatureEncoding::IEEE_P1363;
    default:
      return pb::EcdsaSignatureEncoding::UNKNOWN_ENCODING;
  }
}

// static
const char* Enums::KeyStatusName(pb::KeyStatusType key_status_type) {
  switch (key_status_type) {
    case pb::KeyStatusType::ENABLED:
      return "ENABLED";
    case pb::KeyStatusType::DISABLED:
      return "DISABLED";
    case pb::KeyStatusType::DESTROYED:
      return "DESTROYED";
    default:
      return "UNKNOWN_STATUS";
  }
}

// static
const char* Enums::HashName(pb::HashType hash_type) {
  switch (hash_type) {
    case pb::HashType::SHA1:
      return "SHA1";
    case pb::HashType::SHA224:
      return "SHA224";
    case pb::HashType::SHA256:
      return "SHA256";
    case pb::HashType::SHA384:
      return "SHA384";
    case pb::HashType::SHA512:
      return "SHA512";
    default:
      return "UNKNOWN_HASH";
  }
}

// static
util::StatusOr<int> Enums::HashLength(pb::HashType hash_type) {
  switch (hash_type) {
    case pb::HashType::SHA224:
      return 28;
    case pb::HashType::SHA256:
      return 32;
    case pb::HashType::SHA384:
      return 48;
    case pb::HashType::SHA512:
      return 64;
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          absl::StrCat("Unsupported hashing algorithm ",
                                       util::Enums::HashName(hash_type)));
  }
}

// static
const char* Enums::KeyMaterialName(
    pb::KeyData::KeyMaterialType key_material_type) {
  switch (key_material_type) {
    case pb::KeyData::SYMMETRIC:
      return "SYMMETRIC";
    case pb::KeyData::ASYMMETRIC_PRIVATE:
      return "ASYMMETRIC_PRIVATE";
    case pb::KeyData::ASYMMETRIC_PUBLIC:
      return "ASYMMETRIC_PUBLIC";
    case pb::KeyData::REMOTE:
      return "REMOTE";
    default:
      return "UNKNOWN_KEYMATERIAL";
  }
}

// static
const char* Enums::OutputPrefixName(pb::OutputPrefixType output_prefix_type) {
  switch (output_prefix_type) {
    case pb::OutputPrefixType::TINK:
      return "TINK";
    case pb::OutputPrefixType::LEGACY:
      return "LEGACY";
    case pb::OutputPrefixType::RAW:
      return "RAW";
    case pb::OutputPrefixType::CRUNCHY:
      return "CRUNCHY";
    default:
      return "UNKNOWN_PREFIX";
  }
}

// static
pb::KeyStatusType Enums::KeyStatus(absl::string_view name) {
  if (name == "ENABLED") return pb::KeyStatusType::ENABLED;
  if (name == "DISABLED") return pb::KeyStatusType::DISABLED;
  if (name == "DESTROYED") return pb::KeyStatusType::DESTROYED;
  return pb::KeyStatusType::UNKNOWN_STATUS;
}

// static
pb::HashType Enums::Hash(absl::string_view name) {
  if (name == "SHA1") return pb::HashType::SHA1;
  if (name == "SHA224") return pb::HashType::SHA224;
  if (name == "SHA256") return pb::HashType::SHA256;
  if (name == "SHA384") return pb::HashType::SHA384;
  if (name == "SHA512") return pb::HashType::SHA512;
  return pb::HashType::UNKNOWN_HASH;
}

// static
pb::KeyData::KeyMaterialType Enums::KeyMaterial(absl::string_view name) {
  if (name == "SYMMETRIC") return pb::KeyData::SYMMETRIC;
  if (name == "ASYMMETRIC_PRIVATE") return pb::KeyData::ASYMMETRIC_PRIVATE;
  if (name == "ASYMMETRIC_PUBLIC") return pb::KeyData::ASYMMETRIC_PUBLIC;
  if (name == "REMOTE") return pb::KeyData::REMOTE;
  return pb::KeyData::UNKNOWN_KEYMATERIAL;
}

// static
pb::OutputPrefixType Enums::OutputPrefix(absl::string_view name) {
  if (name == "TINK") return pb::OutputPrefixType::TINK;
  if (name == "LEGACY") return pb::OutputPrefixType::LEGACY;
  if (name == "RAW") return pb::OutputPrefixType::RAW;
  if (name == "CRUNCHY") return pb::OutputPrefixType::CRUNCHY;
  return pb::OutputPrefixType::UNKNOWN_PREFIX;
}

}  // namespace util
}  // namespace tink
}  // namespace crypto
