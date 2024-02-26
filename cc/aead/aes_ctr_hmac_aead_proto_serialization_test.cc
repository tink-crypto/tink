// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#include "tink/aead/aes_ctr_hmac_aead_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_ctr_hmac_aead_parameters.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/parameters.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_ctr.pb.h"
#include "proto/aes_ctr_hmac_aead.pb.h"
#include "proto/common.pb.h"
#include "proto/hmac.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesCtrHmacAeadKeyFormat;
using ::google::crypto::tink::AesCtrKeyFormat;
using ::google::crypto::tink::AesCtrParams;
using ::google::crypto::tink::HashType;
using ::google::crypto::tink::HmacKeyFormat;
using ::google::crypto::tink::HmacParams;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

const absl::string_view kTypeUrl =
    "type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey";

struct TestCase {
  int aes_key_size;
  int hmac_key_size;
  int iv_size;
  int tag_size;
  AesCtrHmacAeadParameters::HashType hash_type;
  HashType proto_hash_type;
  AesCtrHmacAeadParameters::Variant variant;
  OutputPrefixType output_prefix_type;
  absl::optional<int> id_requirement;
  std::string output_prefix;
};

class AesCtrHmacAeadProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  AesCtrHmacAeadProtoSerializationTest() {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

INSTANTIATE_TEST_SUITE_P(
    AesCtrHmacAeadKeyBuildTestSuite, AesCtrHmacAeadProtoSerializationTest,
    Values(TestCase{/*aes_key_size=*/16, /*hmac_key_size=*/16,
                    /*iv_size=*/12, /*tag_size=*/28,
                    AesCtrHmacAeadParameters::HashType::kSha256,
                    HashType::SHA256, AesCtrHmacAeadParameters::Variant::kTink,
                    OutputPrefixType::TINK,
                    /*id_requirement=*/0x02030400,
                    std::string("\x01\x02\x03\x04\x00", 5)},
           TestCase{/*aes_key_size=*/24, /*hmac_key_size=*/32,
                    /*iv_size=*/16, /*tag_size=*/32,
                    AesCtrHmacAeadParameters::HashType::kSha384,
                    HashType::SHA384,
                    AesCtrHmacAeadParameters::Variant::kCrunchy,
                    OutputPrefixType::CRUNCHY,
                    /*id_requirement=*/0x01030005,
                    std::string("\x00\x01\x03\x00\x05", 5)},
           TestCase{/*aes_key_size=*/32, /*hmac_key_size=*/16,
                    /*iv_size=*/16, /*tag_size=*/48,
                    AesCtrHmacAeadParameters::HashType::kSha512,
                    HashType::SHA512,
                    AesCtrHmacAeadParameters::Variant::kNoPrefix,
                    OutputPrefixType::RAW,
                    /*id_requirement=*/absl::nullopt, ""}));

AesCtrHmacAeadKeyFormat BuildAesCtrHmacAeadKeyFormat(int aes_key_size,
                                                     int hmac_key_size,
                                                     int iv_size, int tag_size,
                                                     HashType proto_hash_type,
                                                     int hmac_version) {
  AesCtrHmacAeadKeyFormat aes_ctr_hmac_aead_key_format;
  HmacKeyFormat& hmac_key_format =
      *aes_ctr_hmac_aead_key_format.mutable_hmac_key_format();
  AesCtrKeyFormat& aes_ctr_key_format =
      *aes_ctr_hmac_aead_key_format.mutable_aes_ctr_key_format();

  AesCtrParams& aes_ctr_params = *aes_ctr_key_format.mutable_params();
  aes_ctr_params.set_iv_size(iv_size);
  aes_ctr_key_format.set_key_size(aes_key_size);

  HmacParams& hmac_params = *hmac_key_format.mutable_params();
  hmac_params.set_hash(proto_hash_type);
  hmac_params.set_tag_size(tag_size);
  hmac_key_format.set_key_size(hmac_key_size);
  hmac_key_format.set_version(hmac_version);

  return aes_ctr_hmac_aead_key_format;
}

TEST_F(AesCtrHmacAeadProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());
}

TEST_P(AesCtrHmacAeadProtoSerializationTest, ParseParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());

  AesCtrHmacAeadKeyFormat aes_ctr_hmac_aead_key_format =
      BuildAesCtrHmacAeadKeyFormat(
          test_case.aes_key_size, test_case.hmac_key_size, test_case.iv_size,
          test_case.tag_size, test_case.proto_hash_type, /*hmac_version=*/0);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, test_case.output_prefix_type,
          aes_ctr_hmac_aead_key_format.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> parsed_parameters =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(parsed_parameters, IsOk());
  EXPECT_THAT((*parsed_parameters)->HasIdRequirement(),
              Eq(test_case.id_requirement.has_value()));

  util::StatusOr<AesCtrHmacAeadParameters> expected_parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(test_case.aes_key_size)
          .SetHmacKeySizeInBytes(test_case.hmac_key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(test_case.tag_size)
          .SetHashType(test_case.hash_type)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(expected_parameters, IsOk());
  EXPECT_THAT(**parsed_parameters, Eq(*expected_parameters));
}

TEST_F(AesCtrHmacAeadProtoSerializationTest,
       ParseParametersWithInvalidSerializationFails) {
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());

  AesCtrHmacAeadKeyFormat key_format_proto = BuildAesCtrHmacAeadKeyFormat(
      /*aes_key_size=*/16, /*hmac_key_size=*/16, /*iv_size=*/16,
      /*tag_size=*/16, HashType::SHA256, /*hmac_version=*/0);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  EXPECT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance()
          .ParseParameters(*serialization)
          .status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("Failed to parse AesCtrHmacAeadKeyFormat proto")));
}

TEST_F(AesCtrHmacAeadProtoSerializationTest,
       ParseParametersWithUnkownOutputPrefixFails) {
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());

  AesCtrHmacAeadKeyFormat key_format_proto = BuildAesCtrHmacAeadKeyFormat(
      /*aes_key_size=*/16, /*hmac_key_size=*/16, /*iv_size=*/16,
      /*tag_size=*/16, HashType::SHA256, /*hmac_version=*/0);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::UNKNOWN_PREFIX,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  EXPECT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance()
          .ParseParameters(*serialization)
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Could not determine AesCtrHmacAeadParameters::Variant")));
}

TEST_F(AesCtrHmacAeadProtoSerializationTest,
       ParseParametersWithUnkownHashTypeFails) {
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());

  AesCtrHmacAeadKeyFormat key_format_proto = BuildAesCtrHmacAeadKeyFormat(
      /*aes_key_size=*/16, /*hmac_key_size=*/16, /*iv_size=*/16,
      /*tag_size=*/16, HashType::UNKNOWN_HASH, /*hmac_version=*/0);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  EXPECT_THAT(
      internal::MutableSerializationRegistry::GlobalInstance()
          .ParseParameters(*serialization)
          .status(),
      StatusIs(
          absl::StatusCode::kInvalidArgument,
          HasSubstr("Could not determine AesCtrHmacAeadParameters::HashType")));
}

TEST_F(AesCtrHmacAeadProtoSerializationTest,
       ParseParametersWithInvalidHmacVersionFails) {
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());

  AesCtrHmacAeadKeyFormat key_format_proto = BuildAesCtrHmacAeadKeyFormat(
      /*aes_key_size=*/16, /*hmac_key_size=*/16, /*iv_size=*/16,
      /*tag_size=*/16, HashType::SHA256, /*hmac_version=*/1);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          kTypeUrl, OutputPrefixType::RAW,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  EXPECT_THAT(internal::MutableSerializationRegistry::GlobalInstance()
                  .ParseParameters(*serialization)
                  .status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("only version 0 is accepted")));
}

TEST_P(AesCtrHmacAeadProtoSerializationTest, SerializeParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterAesCtrHmacAeadProtoSerialization(), IsOk());

  util::StatusOr<AesCtrHmacAeadParameters> parameters =
      AesCtrHmacAeadParameters::Builder()
          .SetAesKeySizeInBytes(test_case.aes_key_size)
          .SetHmacKeySizeInBytes(test_case.hmac_key_size)
          .SetIvSizeInBytes(test_case.iv_size)
          .SetTagSizeInBytes(test_case.tag_size)
          .SetHashType(test_case.hash_type)
          .SetVariant(test_case.variant)
          .Build();
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(
              *parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kTypeUrl));

  const internal::ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const internal::ProtoParametersSerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());

  EXPECT_THAT(proto_serialization->GetKeyTemplate().type_url(), Eq(kTypeUrl));
  EXPECT_THAT(proto_serialization->GetKeyTemplate().output_prefix_type(),
              Eq(test_case.output_prefix_type));

  AesCtrHmacAeadKeyFormat aes_ctr_hmac_aead_key_format;
  ASSERT_THAT(aes_ctr_hmac_aead_key_format.ParseFromString(
                  proto_serialization->GetKeyTemplate().value()),
              IsTrue());
  ASSERT_THAT(aes_ctr_hmac_aead_key_format.aes_ctr_key_format().key_size(),
              Eq(test_case.aes_key_size));
  ASSERT_THAT(
      aes_ctr_hmac_aead_key_format.aes_ctr_key_format().params().iv_size(),
      Eq(test_case.iv_size));
  ASSERT_THAT(aes_ctr_hmac_aead_key_format.hmac_key_format().key_size(),
              Eq(test_case.hmac_key_size));
  ASSERT_THAT(
      aes_ctr_hmac_aead_key_format.hmac_key_format().params().tag_size(),
      Eq(test_case.tag_size));
  ASSERT_THAT(aes_ctr_hmac_aead_key_format.hmac_key_format().params().hash(),
              Eq(test_case.proto_hash_type));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
