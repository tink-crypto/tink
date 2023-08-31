// Copyright 2023 Google LLC
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

#include "tink/aead/aes_gcm_siv_proto_serialization.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/types/optional.h"
#include "tink/aead/aes_gcm_siv_parameters.h"
#include "tink/internal/mutable_serialization_registry.h"
#include "tink/internal/proto_parameters_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/parameters.h"
#include "tink/subtle/random.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_gcm_siv.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::AesGcmSivKeyFormat;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::IsTrue;
using ::testing::NotNull;
using ::testing::TestWithParam;
using ::testing::Values;

struct TestCase {
  AesGcmSivParameters::Variant variant;
  OutputPrefixType output_prefix_type;
  int key_size;
  absl::optional<int> id;
  std::string output_prefix;
};

class AesGcmSivProtoSerializationTest : public TestWithParam<TestCase> {
 protected:
  void SetUp() override {
    internal::MutableSerializationRegistry::GlobalInstance().Reset();
  }
};

TEST_F(AesGcmSivProtoSerializationTest, RegisterTwiceSucceeds) {
  ASSERT_THAT(RegisterAesGcmSivProtoSerialization(), IsOk());
  ASSERT_THAT(RegisterAesGcmSivProtoSerialization(), IsOk());
}

INSTANTIATE_TEST_SUITE_P(
    AesGcmSivProtoSerializationTestSuite, AesGcmSivProtoSerializationTest,
    Values(
        TestCase{AesGcmSivParameters::Variant::kTink, OutputPrefixType::TINK,
                 /*key_size=*/16, /*id=*/0x02030400,
                 /*output_prefix=*/std::string("\x01\x02\x03\x04\x00", 5)},
        TestCase{AesGcmSivParameters::Variant::kCrunchy,
                 OutputPrefixType::CRUNCHY, /*key_size=*/16, /*id=*/0x01030005,
                 /*output_prefix=*/std::string("\x00\x01\x03\x00\x05", 5)},
        TestCase{AesGcmSivParameters::Variant::kNoPrefix, OutputPrefixType::RAW,
                 /*key_size=*/32, /*id=*/absl::nullopt, /*output_prefix=*/""}));

TEST_P(AesGcmSivProtoSerializationTest, ParseParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterAesGcmSivProtoSerialization(), IsOk());

  AesGcmSivKeyFormat key_format_proto;
  key_format_proto.set_version(0);
  key_format_proto.set_key_size(test_case.key_size);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesGcmSivKey",
          test_case.output_prefix_type, key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), test_case.id.has_value());

  const AesGcmSivParameters* gcm_siv_params =
      dynamic_cast<const AesGcmSivParameters*>(params->get());
  ASSERT_THAT(gcm_siv_params, NotNull());
  EXPECT_THAT(gcm_siv_params->GetVariant(), Eq(test_case.variant));
  EXPECT_THAT(gcm_siv_params->KeySizeInBytes(), Eq(test_case.key_size));
}

TEST_F(AesGcmSivProtoSerializationTest,
       ParseParametersWithInvalidSerialization) {
  ASSERT_THAT(RegisterAesGcmSivProtoSerialization(), IsOk());

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesGcmSivKey",
          OutputPrefixType::RAW, "invalid_serialization");
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesGcmSivProtoSerializationTest, ParseParametersWithUnkownOutputPrefix) {
  ASSERT_THAT(RegisterAesGcmSivProtoSerialization(), IsOk());

  AesGcmSivKeyFormat key_format_proto;
  key_format_proto.set_version(0);
  key_format_proto.set_key_size(16);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesGcmSivKey",
          OutputPrefixType::UNKNOWN_PREFIX,
          key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AesGcmSivProtoSerializationTest, ParseParametersWithInvalidVersion) {
  ASSERT_THAT(RegisterAesGcmSivProtoSerialization(), IsOk());

  AesGcmSivKeyFormat key_format_proto;
  key_format_proto.set_version(1);
  key_format_proto.set_key_size(16);

  util::StatusOr<internal::ProtoParametersSerialization> serialization =
      internal::ProtoParametersSerialization::Create(
          "type.googleapis.com/google.crypto.tink.AesGcmSivKey",
          OutputPrefixType::RAW, key_format_proto.SerializeAsString());
  ASSERT_THAT(serialization, IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      internal::MutableSerializationRegistry::GlobalInstance().ParseParameters(
          *serialization);
  EXPECT_THAT(params.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(AesGcmSivProtoSerializationTest, SerializeParameters) {
  TestCase test_case = GetParam();
  ASSERT_THAT(RegisterAesGcmSivProtoSerialization(), IsOk());

  util::StatusOr<AesGcmSivParameters> parameters =
      AesGcmSivParameters::Create(test_case.key_size, test_case.variant);
  ASSERT_THAT(parameters, IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      internal::MutableSerializationRegistry::GlobalInstance()
          .SerializeParameters<internal::ProtoParametersSerialization>(
              *parameters);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(),
              Eq("type.googleapis.com/google.crypto.tink.AesGcmSivKey"));

  const internal::ProtoParametersSerialization* proto_serialization =
      dynamic_cast<const internal::ProtoParametersSerialization*>(
          serialization->get());
  ASSERT_THAT(proto_serialization, NotNull());
  EXPECT_THAT(proto_serialization->GetKeyTemplate().type_url(),
              Eq("type.googleapis.com/google.crypto.tink.AesGcmSivKey"));
  EXPECT_THAT(proto_serialization->GetKeyTemplate().output_prefix_type(),
              Eq(test_case.output_prefix_type));

  AesGcmSivKeyFormat key_format;
  ASSERT_THAT(
      key_format.ParseFromString(proto_serialization->GetKeyTemplate().value()),
      IsTrue());
  EXPECT_THAT(key_format.key_size(), Eq(test_case.key_size));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
