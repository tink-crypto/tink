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

#include "tink/subtle/common_enums.h"
#include "gtest/gtest.h"
#include "proto/common.pb.h"

using crypto::tink::util::Enums;

namespace pb = google::crypto::tink;

namespace crypto {
namespace tink {
namespace {

class EnumsTest : public ::testing::Test {
};

TEST_F(EnumsTest, testEllipticCurveType) {
  EXPECT_EQ(pb::EllipticCurveType::NIST_P256,
            Enums::SubtleToProto(subtle::EllipticCurveType::NIST_P256));
  EXPECT_EQ(pb::EllipticCurveType::NIST_P384,
            Enums::SubtleToProto(subtle::EllipticCurveType::NIST_P384));
  EXPECT_EQ(pb::EllipticCurveType::NIST_P521,
            Enums::SubtleToProto(subtle::EllipticCurveType::NIST_P521));
  EXPECT_EQ(pb::EllipticCurveType::UNKNOWN_CURVE,
            Enums::SubtleToProto(subtle::EllipticCurveType::UNKNOWN_CURVE));
  EXPECT_EQ(pb::EllipticCurveType::UNKNOWN_CURVE,
            Enums::SubtleToProto((subtle::EllipticCurveType)42));

  EXPECT_EQ(subtle::EllipticCurveType::NIST_P256,
            Enums::ProtoToSubtle(pb::EllipticCurveType::NIST_P256));
  EXPECT_EQ(subtle::EllipticCurveType::NIST_P384,
            Enums::ProtoToSubtle(pb::EllipticCurveType::NIST_P384));
  EXPECT_EQ(subtle::EllipticCurveType::NIST_P521,
            Enums::ProtoToSubtle(pb::EllipticCurveType::NIST_P521));
  EXPECT_EQ(subtle::EllipticCurveType::UNKNOWN_CURVE,
            Enums::ProtoToSubtle(pb::EllipticCurveType::UNKNOWN_CURVE));
  EXPECT_EQ(subtle::EllipticCurveType::UNKNOWN_CURVE,
            Enums::ProtoToSubtle((pb::EllipticCurveType)42));

  // Check that enum conversion covers the entire range of the proto-enum.
  int count = 0;
  for (int int_type = (int)pb::EllipticCurveType_MIN;
       int_type <= (int)pb::EllipticCurveType_MAX;
       int_type++) {
    if (pb::EllipticCurveType_IsValid(int_type)) {
      pb::EllipticCurveType type = (pb::EllipticCurveType)int_type;
      EXPECT_EQ(type,
                Enums::SubtleToProto(Enums::ProtoToSubtle(type)));
      count++;
    }
  }
  EXPECT_EQ(4, count);
}

TEST_F(EnumsTest, testHashType) {
  EXPECT_EQ(pb::HashType::SHA1,
            Enums::SubtleToProto(subtle::HashType::SHA1));
  EXPECT_EQ(pb::HashType::SHA256,
            Enums::SubtleToProto(subtle::HashType::SHA256));
  EXPECT_EQ(pb::HashType::SHA512,
            Enums::SubtleToProto(subtle::HashType::SHA512));
  EXPECT_EQ(pb::HashType::UNKNOWN_HASH,
            Enums::SubtleToProto(subtle::HashType::UNKNOWN_HASH));
  EXPECT_EQ(pb::HashType::UNKNOWN_HASH,
            Enums::SubtleToProto((subtle::HashType)42));

  EXPECT_EQ(subtle::HashType::SHA1,
            Enums::ProtoToSubtle(pb::HashType::SHA1));
  EXPECT_EQ(subtle::HashType::SHA256,
            Enums::ProtoToSubtle(pb::HashType::SHA256));
  EXPECT_EQ(subtle::HashType::SHA512,
            Enums::ProtoToSubtle(pb::HashType::SHA512));
  EXPECT_EQ(subtle::HashType::UNKNOWN_HASH,
            Enums::ProtoToSubtle(pb::HashType::UNKNOWN_HASH));
  EXPECT_EQ(subtle::HashType::UNKNOWN_HASH,
            Enums::ProtoToSubtle((pb::HashType)42));

  // Check that enum conversion covers the entire range of the proto-enum.
  int count = 0;
  for (int int_type = (int)pb::HashType_MIN;
       int_type <= (int)pb::HashType_MAX;
       int_type++) {
    if (pb::HashType_IsValid(int_type)) {
      pb::HashType type = (pb::HashType)int_type;
      EXPECT_EQ(type,
                Enums::SubtleToProto(Enums::ProtoToSubtle(type)));
      count++;
    }
  }
  EXPECT_EQ(4, count);
}

TEST_F(EnumsTest, testEcPointFormat) {
  EXPECT_EQ(pb::EcPointFormat::UNCOMPRESSED,
            Enums::SubtleToProto(subtle::EcPointFormat::UNCOMPRESSED));
  EXPECT_EQ(pb::EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED,
            Enums::SubtleToProto(
                subtle::EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED));
  EXPECT_EQ(pb::EcPointFormat::COMPRESSED,
            Enums::SubtleToProto(subtle::EcPointFormat::COMPRESSED));
  EXPECT_EQ(pb::EcPointFormat::UNKNOWN_FORMAT,
            Enums::SubtleToProto(subtle::EcPointFormat::UNKNOWN_FORMAT));
  EXPECT_EQ(pb::EcPointFormat::UNKNOWN_FORMAT,
            Enums::SubtleToProto((subtle::EcPointFormat)42));

  EXPECT_EQ(subtle::EcPointFormat::UNCOMPRESSED,
            Enums::ProtoToSubtle(pb::EcPointFormat::UNCOMPRESSED));
  EXPECT_EQ(
      subtle::EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED,
      Enums::ProtoToSubtle(pb::EcPointFormat::DO_NOT_USE_CRUNCHY_UNCOMPRESSED));
  EXPECT_EQ(subtle::EcPointFormat::COMPRESSED,
            Enums::ProtoToSubtle(pb::EcPointFormat::COMPRESSED));
  EXPECT_EQ(subtle::EcPointFormat::UNKNOWN_FORMAT,
            Enums::ProtoToSubtle(pb::EcPointFormat::UNKNOWN_FORMAT));
  EXPECT_EQ(subtle::EcPointFormat::UNKNOWN_FORMAT,
            Enums::ProtoToSubtle((pb::EcPointFormat)42));

  // Check that enum conversion covers the entire range of the proto-enum.
  int count = 0;
  for (int int_format = (int)pb::EcPointFormat_MIN;
       int_format <= (int)pb::EcPointFormat_MAX;
       int_format++) {
    if (pb::EcPointFormat_IsValid(int_format)) {
      pb::EcPointFormat format = (pb::EcPointFormat)int_format;
      EXPECT_EQ(format,
                Enums::SubtleToProto(Enums::ProtoToSubtle(format)));
      count++;
    }
  }
  EXPECT_EQ(4, count);
}

TEST_F(EnumsTest, testEcdsaSignatureEncoding) {
  EXPECT_EQ(
      pb::EcdsaSignatureEncoding::UNKNOWN_ENCODING,
      Enums::SubtleToProto(subtle::EcdsaSignatureEncoding::UNKNOWN_ENCODING));
  EXPECT_EQ(pb::EcdsaSignatureEncoding::IEEE_P1363,
            Enums::SubtleToProto(subtle::EcdsaSignatureEncoding::IEEE_P1363));
  EXPECT_EQ(pb::EcdsaSignatureEncoding::DER,
            Enums::SubtleToProto(subtle::EcdsaSignatureEncoding::DER));
  EXPECT_EQ(subtle::EcdsaSignatureEncoding::UNKNOWN_ENCODING,
            Enums::ProtoToSubtle(pb::EcdsaSignatureEncoding::UNKNOWN_ENCODING));
  EXPECT_EQ(subtle::EcdsaSignatureEncoding::IEEE_P1363,
            Enums::ProtoToSubtle(pb::EcdsaSignatureEncoding::IEEE_P1363));
  EXPECT_EQ(subtle::EcdsaSignatureEncoding::DER,
            Enums::ProtoToSubtle(pb::EcdsaSignatureEncoding::DER));
  // Check that enum conversion covers the entire range of the proto-enum.
  int count = 0;
  for (int int_encoding = (int)pb::EcdsaSignatureEncoding_MIN;
       int_encoding <= (int)pb::EcdsaSignatureEncoding_MAX; int_encoding++) {
    if (pb::EcdsaSignatureEncoding_IsValid(int_encoding)) {
      pb::EcdsaSignatureEncoding encoding =
          (pb::EcdsaSignatureEncoding)int_encoding;
      EXPECT_EQ(encoding, Enums::SubtleToProto(Enums::ProtoToSubtle(encoding)));
      count++;
    }
  }
  EXPECT_EQ(3, count);
}

TEST_F(EnumsTest, testKeyStatusName) {
  EXPECT_EQ("ENABLED",
            std::string(Enums::KeyStatusName(pb::KeyStatusType::ENABLED)));
  EXPECT_EQ("DISABLED",
            std::string(Enums::KeyStatusName(pb::KeyStatusType::DISABLED)));
  EXPECT_EQ("DESTROYED",
            std::string(Enums::KeyStatusName(pb::KeyStatusType::DESTROYED)));
  EXPECT_EQ("UNKNOWN_STATUS",
            std::string(Enums::KeyStatusName(pb::KeyStatusType::UNKNOWN_STATUS)));
  EXPECT_EQ("UNKNOWN_STATUS",
            std::string(Enums::KeyStatusName((pb::KeyStatusType)42)));

  EXPECT_EQ(pb::KeyStatusType::ENABLED, Enums::KeyStatus("ENABLED"));
  EXPECT_EQ(pb::KeyStatusType::DISABLED, Enums::KeyStatus("DISABLED"));
  EXPECT_EQ(pb::KeyStatusType::DESTROYED, Enums::KeyStatus("DESTROYED"));
  EXPECT_EQ(pb::KeyStatusType::UNKNOWN_STATUS,
            Enums::KeyStatus("Other string"));
  EXPECT_EQ(pb::KeyStatusType::UNKNOWN_STATUS,
            Enums::KeyStatus("UNKNOWN_STATUS"));

  // Check that enum conversion covers the entire range of the proto-enum.
  int count = 0;
  for (int int_status = (int)pb::KeyStatusType_MIN;
       int_status <= (int)pb::KeyStatusType_MAX;
       int_status++) {
    if (pb::KeyStatusType_IsValid(int_status)) {
      pb::KeyStatusType status = (pb::KeyStatusType)int_status;
      EXPECT_EQ(status,
                Enums::KeyStatus(Enums::KeyStatusName(status)));
      count++;
    }
  }
  EXPECT_EQ(4, count);
}

TEST_F(EnumsTest, testHashName) {
  EXPECT_EQ("SHA1", std::string(Enums::HashName(pb::HashType::SHA1)));
  EXPECT_EQ("SHA256", std::string(Enums::HashName(pb::HashType::SHA256)));
  EXPECT_EQ("SHA512", std::string(Enums::HashName(pb::HashType::SHA512)));
  EXPECT_EQ("UNKNOWN_HASH",
            std::string(Enums::HashName(pb::HashType::UNKNOWN_HASH)));
  EXPECT_EQ("UNKNOWN_HASH",
            std::string(Enums::HashName((pb::HashType)42)));

  EXPECT_EQ(pb::HashType::SHA1, Enums::Hash("SHA1"));
  EXPECT_EQ(pb::HashType::SHA256, Enums::Hash("SHA256"));
  EXPECT_EQ(pb::HashType::SHA512, Enums::Hash("SHA512"));
  EXPECT_EQ(pb::HashType::UNKNOWN_HASH, Enums::Hash("Other string"));
  EXPECT_EQ(pb::HashType::UNKNOWN_HASH, Enums::Hash("UNKNOWN_HASH"));

  // Check that enum conversion covers the entire range of the proto-enum.
  int count = 0;
  for (int int_hash = (int)pb::HashType_MIN;
       int_hash <= (int)pb::HashType_MAX;
       int_hash++) {
    if (pb::HashType_IsValid(int_hash)) {
      pb::HashType hash = (pb::HashType)int_hash;
      EXPECT_EQ(hash, Enums::Hash(Enums::HashName(hash)));
      count++;
    }
  }
  EXPECT_EQ(4, count);
}

TEST_F(EnumsTest, testKeyMaterialName) {
  EXPECT_EQ("SYMMETRIC",
            std::string(Enums::KeyMaterialName(pb::KeyData::SYMMETRIC)));
  EXPECT_EQ("ASYMMETRIC_PRIVATE",
            std::string(Enums::KeyMaterialName(pb::KeyData::ASYMMETRIC_PRIVATE)));
  EXPECT_EQ("ASYMMETRIC_PUBLIC",
            std::string(Enums::KeyMaterialName(pb::KeyData::ASYMMETRIC_PUBLIC)));
  EXPECT_EQ("REMOTE",
            std::string(Enums::KeyMaterialName(pb::KeyData::REMOTE)));
  EXPECT_EQ("UNKNOWN_KEYMATERIAL",
            std::string(Enums::KeyMaterialName(pb::KeyData::UNKNOWN_KEYMATERIAL)));
  EXPECT_EQ("UNKNOWN_KEYMATERIAL",
            std::string(Enums::KeyMaterialName((pb::KeyData::KeyMaterialType)42)));

  EXPECT_EQ(pb::KeyData::SYMMETRIC,
            Enums::KeyMaterial("SYMMETRIC"));
  EXPECT_EQ(pb::KeyData::ASYMMETRIC_PRIVATE,
            Enums::KeyMaterial("ASYMMETRIC_PRIVATE"));
  EXPECT_EQ(pb::KeyData::ASYMMETRIC_PUBLIC,
            Enums::KeyMaterial("ASYMMETRIC_PUBLIC"));
  EXPECT_EQ(pb::KeyData::REMOTE,
            Enums::KeyMaterial("REMOTE"));
  EXPECT_EQ(pb::KeyData::UNKNOWN_KEYMATERIAL,
            Enums::KeyMaterial("Other string"));
  EXPECT_EQ(pb::KeyData::UNKNOWN_KEYMATERIAL,
            Enums::KeyMaterial("UNKNOWN_KEYMATERIAL"));

  // Check that enum conversion covers the entire range of the proto-enum.
  int count = 0;
  for (int int_type = (int)pb::KeyData::KeyMaterialType_MIN;
       int_type <= (int)pb::KeyData::KeyMaterialType_MAX;
       int_type++) {
    if (pb::KeyData::KeyMaterialType_IsValid(int_type)) {
      pb::KeyData::KeyMaterialType type =
          (pb::KeyData::KeyMaterialType)int_type;
      EXPECT_EQ(type,
                Enums::KeyMaterial(Enums::KeyMaterialName(type)));
      count++;
    }
  }
  EXPECT_EQ(5, count);
}

TEST_F(EnumsTest, testOutputPrefixName) {
  EXPECT_EQ("TINK",
            std::string(Enums::OutputPrefixName(pb::OutputPrefixType::TINK)));
  EXPECT_EQ("LEGACY",
            std::string(Enums::OutputPrefixName(pb::OutputPrefixType::LEGACY)));
  EXPECT_EQ("RAW",
            std::string(Enums::OutputPrefixName(pb::OutputPrefixType::RAW)));
  EXPECT_EQ("CRUNCHY",
            std::string(Enums::OutputPrefixName(pb::OutputPrefixType::CRUNCHY)));
  EXPECT_EQ("UNKNOWN_PREFIX",
            std::string(Enums::OutputPrefixName(
                pb::OutputPrefixType::UNKNOWN_PREFIX)));
  EXPECT_EQ("UNKNOWN_PREFIX",
            std::string(Enums::OutputPrefixName((pb::OutputPrefixType)42)));

  EXPECT_EQ(pb::OutputPrefixType::TINK, Enums::OutputPrefix("TINK"));
  EXPECT_EQ(pb::OutputPrefixType::LEGACY, Enums::OutputPrefix("LEGACY"));
  EXPECT_EQ(pb::OutputPrefixType::RAW, Enums::OutputPrefix("RAW"));
  EXPECT_EQ(pb::OutputPrefixType::CRUNCHY, Enums::OutputPrefix("CRUNCHY"));
  EXPECT_EQ(pb::OutputPrefixType::UNKNOWN_PREFIX,
            Enums::OutputPrefix("Other string"));
  EXPECT_EQ(pb::OutputPrefixType::UNKNOWN_PREFIX,
            Enums::OutputPrefix("UNKNOWN_PREFIX"));

  // Check that enum conversion covers the entire range of the proto-enum.
  int count = 0;
  for (int int_type = (int)pb::OutputPrefixType_MIN;
       int_type <= (int)pb::OutputPrefixType_MAX;
       int_type++) {
    if (pb::OutputPrefixType_IsValid(int_type)) {
      pb::OutputPrefixType type = (pb::OutputPrefixType)int_type;
      EXPECT_EQ(type, Enums::OutputPrefix(Enums::OutputPrefixName(type)));
      count++;
    }
  }
  EXPECT_EQ(5, count);
}

}  // namespace
}  // namespace tink
}  // namespace crypto
