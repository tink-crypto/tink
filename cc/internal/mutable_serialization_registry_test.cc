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

#include "tink/internal/mutable_serialization_registry.h"

#include <memory>
#include <string_view>
#include <typeindex>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/proto_key_serialization.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_test_util.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/restricted_data.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::OutputPrefixType;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsTrue;

TEST(MutableSerializationRegistryTest, ParseParameters) {
  MutableSerializationRegistry registry;
  ParametersParserImpl<NoIdSerialization, NoIdParams> parser1(kNoIdTypeUrl,
                                                              ParseNoIdParams);
  ParametersParserImpl<IdParamsSerialization, IdParams> parser2(kIdTypeUrl,
                                                                ParseIdParams);
  ASSERT_THAT(registry.RegisterParametersParser(&parser1), IsOk());
  ASSERT_THAT(registry.RegisterParametersParser(&parser2), IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> no_id_params =
      registry.ParseParameters(NoIdSerialization());
  ASSERT_THAT(no_id_params, IsOk());
  EXPECT_THAT((*no_id_params)->HasIdRequirement(), IsFalse());
  EXPECT_THAT(std::type_index(typeid(**no_id_params)),
              std::type_index(typeid(NoIdParams)));

  util::StatusOr<std::unique_ptr<Parameters>> id_params =
      registry.ParseParameters(IdParamsSerialization());
  ASSERT_THAT(id_params, IsOk());
  EXPECT_THAT((*id_params)->HasIdRequirement(), IsTrue());
  EXPECT_THAT(std::type_index(typeid(**id_params)),
              std::type_index(typeid(IdParams)));
}

TEST(MutableSerializationRegistryTest, ParseParametersWithoutRegistration) {
  MutableSerializationRegistry registry;

  ASSERT_THAT(registry.ParseParameters(NoIdSerialization()).status(),
              StatusIs(absl::StatusCode::kNotFound));
}

TEST(MutableSerializationRegistryTest, RegisterSameParametersParser) {
  MutableSerializationRegistry registry;
  ParametersParserImpl<NoIdSerialization, NoIdParams> parser(kNoIdTypeUrl,
                                                             ParseNoIdParams);

  EXPECT_THAT(registry.RegisterParametersParser(&parser), IsOk());
  EXPECT_THAT(registry.RegisterParametersParser(&parser), IsOk());
}

TEST(MutableSerializationRegistryTest,
     RegisterDifferentParametersParserWithSameIndex) {
  MutableSerializationRegistry registry;
  ParametersParserImpl<NoIdSerialization, NoIdParams> parser1(kNoIdTypeUrl,
                                                              ParseNoIdParams);
  ParametersParserImpl<NoIdSerialization, NoIdParams> parser2(kNoIdTypeUrl,
                                                              ParseNoIdParams);

  EXPECT_THAT(registry.RegisterParametersParser(&parser1), IsOk());
  EXPECT_THAT(registry.RegisterParametersParser(&parser2),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

TEST(MutableSerializationRegistryTest, SerializeParameters) {
  MutableSerializationRegistry registry;
  ParametersSerializerImpl<NoIdParams, NoIdSerialization> serializer1(
      kNoIdTypeUrl, SerializeNoIdParams);
  ParametersSerializerImpl<IdParams, IdParamsSerialization> serializer2(
      kIdTypeUrl, SerializeIdParams);
  ASSERT_THAT(registry.RegisterParametersSerializer(&serializer1), IsOk());
  ASSERT_THAT(registry.RegisterParametersSerializer(&serializer2), IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization1 =
      registry.SerializeParameters<NoIdSerialization>(NoIdParams());
  ASSERT_THAT(serialization1, IsOk());
  EXPECT_THAT((*serialization1)->ObjectIdentifier(), Eq(kNoIdTypeUrl));

  util::StatusOr<std::unique_ptr<Serialization>> serialization2 =
      registry.SerializeParameters<IdParamsSerialization>(IdParams());
  ASSERT_THAT(serialization2, IsOk());
  EXPECT_THAT((*serialization2)->ObjectIdentifier(), Eq(kIdTypeUrl));
}

TEST(MutableSerializationRegistryTest, SerializeParametersWithoutRegistration) {
  MutableSerializationRegistry registry;

  ASSERT_THAT(
      registry.SerializeParameters<NoIdSerialization>(NoIdParams()).status(),
      StatusIs(absl::StatusCode::kNotFound));
}

TEST(MutableSerializationRegistryTest, RegisterSameParametersSerializer) {
  MutableSerializationRegistry registry;
  ParametersSerializerImpl<NoIdParams, NoIdSerialization> serializer(
      kNoIdTypeUrl, SerializeNoIdParams);

  EXPECT_THAT(registry.RegisterParametersSerializer(&serializer), IsOk());
  EXPECT_THAT(registry.RegisterParametersSerializer(&serializer), IsOk());
}

TEST(MutableSerializationRegistryTest,
     RegisterDifferentParametersSerializerWithSameIndex) {
  MutableSerializationRegistry registry;
  ParametersSerializerImpl<NoIdParams, NoIdSerialization> serializer1(
      kNoIdTypeUrl, SerializeNoIdParams);
  ParametersSerializerImpl<NoIdParams, NoIdSerialization> serializer2(
      kNoIdTypeUrl, SerializeNoIdParams);

  EXPECT_THAT(registry.RegisterParametersSerializer(&serializer1), IsOk());
  EXPECT_THAT(registry.RegisterParametersSerializer(&serializer2),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

TEST(MutableSerializationRegistryTest, ParseKey) {
  MutableSerializationRegistry registry;
  KeyParserImpl<NoIdSerialization, NoIdKey> parser1(kNoIdTypeUrl, ParseNoIdKey);
  KeyParserImpl<IdKeySerialization, IdKey> parser2(kIdTypeUrl, ParseIdKey);
  ASSERT_THAT(registry.RegisterKeyParser(&parser1), IsOk());
  ASSERT_THAT(registry.RegisterKeyParser(&parser2), IsOk());

  util::StatusOr<std::unique_ptr<Key>> no_id_key =
      registry.ParseKey(NoIdSerialization());
  ASSERT_THAT(no_id_key, IsOk());
  EXPECT_THAT(std::type_index(typeid(**no_id_key)),
              std::type_index(typeid(NoIdKey)));

  util::StatusOr<std::unique_ptr<Key>> id_key =
      registry.ParseKey(IdKeySerialization(/*id=*/123));
  ASSERT_THAT(id_key, IsOk());
  EXPECT_THAT(std::type_index(typeid(**id_key)),
              std::type_index(typeid(IdKey)));
  EXPECT_THAT((*id_key)->GetIdRequirement(), Eq(123));
}

TEST(MutableSerializationRegistryTest, ParseKeyWithLegacyFallback) {
  MutableSerializationRegistry registry;
  KeyParserImpl<IdKeySerialization, IdKey> parser(kIdTypeUrl, ParseIdKey);
  ASSERT_THAT(registry.RegisterKeyParser(&parser), IsOk());

  // Parse key with registered key parser.
  util::StatusOr<std::unique_ptr<Key>> id_key =
      registry.ParseKeyWithLegacyFallback(IdKeySerialization(/*id=*/123));
  ASSERT_THAT(id_key, IsOk());
  EXPECT_THAT(std::type_index(typeid(**id_key)),
              std::type_index(typeid(IdKey)));
  EXPECT_THAT((*id_key)->GetIdRequirement(), Eq(123));

  RestrictedData serialized_key =
      RestrictedData("serialized_key", InsecureSecretKeyAccess::Get());
  util::StatusOr<ProtoKeySerialization> serialization =
      ProtoKeySerialization::Create("type_url", serialized_key,
                                    KeyData::SYMMETRIC, OutputPrefixType::TINK,
                                    /*id_requirement=*/456);
  ASSERT_THAT(serialization.status(), IsOk());

  // Fall back to legacy proto key.
  util::StatusOr<std::unique_ptr<Key>> proto_key =
      registry.ParseKeyWithLegacyFallback(*serialization);
  ASSERT_THAT(proto_key, IsOk());
  EXPECT_THAT((*proto_key)->GetIdRequirement(), Eq(456));
}

TEST(MutableSerializationRegistryTest, ParseKeyWithoutRegistration) {
  MutableSerializationRegistry registry;

  ASSERT_THAT(registry.ParseKey(NoIdSerialization()).status(),
              StatusIs(absl::StatusCode::kNotFound));
}

TEST(MutableSerializationRegistryTest, RegisterSameKeyParser) {
  MutableSerializationRegistry registry;
  KeyParserImpl<NoIdSerialization, NoIdKey> parser(kNoIdTypeUrl, ParseNoIdKey);

  EXPECT_THAT(registry.RegisterKeyParser(&parser), IsOk());
  EXPECT_THAT(registry.RegisterKeyParser(&parser), IsOk());
}

TEST(MutableSerializationRegistryTest,
     RegisterDifferentKeyParserWithSameIndex) {
  MutableSerializationRegistry registry;
  KeyParserImpl<NoIdSerialization, NoIdKey> parser1(kNoIdTypeUrl, ParseNoIdKey);
  KeyParserImpl<NoIdSerialization, NoIdKey> parser2(kNoIdTypeUrl, ParseNoIdKey);

  EXPECT_THAT(registry.RegisterKeyParser(&parser1), IsOk());
  EXPECT_THAT(registry.RegisterKeyParser(&parser2),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

TEST(MutableSerializationRegistryTest, SerializeKey) {
  MutableSerializationRegistry registry;
  KeySerializerImpl<NoIdKey, NoIdSerialization> serializer1(SerializeNoIdKey);
  KeySerializerImpl<IdKey, IdKeySerialization> serializer2(SerializeIdKey);
  ASSERT_THAT(registry.RegisterKeySerializer(&serializer1), IsOk());
  ASSERT_THAT(registry.RegisterKeySerializer(&serializer2), IsOk());

  util::StatusOr<std::unique_ptr<Serialization>> serialization1 =
      registry.SerializeKey<NoIdSerialization>(NoIdKey());
  ASSERT_THAT(serialization1, IsOk());
  EXPECT_THAT((*serialization1)->ObjectIdentifier(), Eq(kNoIdTypeUrl));

  util::StatusOr<std::unique_ptr<Serialization>> serialization2 =
      registry.SerializeKey<IdKeySerialization>(IdKey(123));
  ASSERT_THAT(serialization2, IsOk());
  EXPECT_THAT((*serialization2)->ObjectIdentifier(), Eq(kIdTypeUrl));
}

TEST(MutableSerializationRegistryTest, SerializeKeyWithoutRegistration) {
  MutableSerializationRegistry registry;

  ASSERT_THAT(registry.SerializeKey<NoIdSerialization>(NoIdKey()).status(),
              StatusIs(absl::StatusCode::kNotFound));
}

TEST(MutableSerializationRegistryTest, RegisterSameKeySerializer) {
  MutableSerializationRegistry registry;
  KeySerializerImpl<NoIdKey, NoIdSerialization> serializer(SerializeNoIdKey);

  EXPECT_THAT(registry.RegisterKeySerializer(&serializer), IsOk());
  EXPECT_THAT(registry.RegisterKeySerializer(&serializer), IsOk());
}

TEST(MutableSerializationRegistryTest,
     RegisterDifferentKeySerializerWithSameIndex) {
  MutableSerializationRegistry registry;
  KeySerializerImpl<NoIdKey, NoIdSerialization> serializer1(SerializeNoIdKey);
  KeySerializerImpl<NoIdKey, NoIdSerialization> serializer2(SerializeNoIdKey);

  EXPECT_THAT(registry.RegisterKeySerializer(&serializer1), IsOk());
  EXPECT_THAT(registry.RegisterKeySerializer(&serializer2),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

TEST(MutableSerializationRegistryTest, Reset) {
  MutableSerializationRegistry registry;
  ParametersParserImpl<NoIdSerialization, NoIdParams> params_parser(
      kNoIdTypeUrl, ParseNoIdParams);
  ParametersSerializerImpl<NoIdParams, NoIdSerialization> params_serializer(
      kNoIdTypeUrl, SerializeNoIdParams);
  KeyParserImpl<NoIdSerialization, NoIdKey> key_parser(kNoIdTypeUrl,
                                                       ParseNoIdKey);
  KeySerializerImpl<NoIdKey, NoIdSerialization> key_serializer(
      SerializeNoIdKey);

  ASSERT_THAT(registry.RegisterParametersParser(&params_parser), IsOk());
  ASSERT_THAT(registry.RegisterParametersSerializer(&params_serializer),
              IsOk());
  ASSERT_THAT(registry.RegisterKeyParser(&key_parser), IsOk());
  ASSERT_THAT(registry.RegisterKeySerializer(&key_serializer), IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      registry.ParseParameters(NoIdSerialization());
  ASSERT_THAT(params, IsOk());
  util::StatusOr<std::unique_ptr<Serialization>> serialization1 =
      registry.SerializeParameters<NoIdSerialization>(NoIdParams());
  ASSERT_THAT(serialization1, IsOk());
  util::StatusOr<std::unique_ptr<Key>> key =
      registry.ParseKey(NoIdSerialization());
  ASSERT_THAT(key, IsOk());
  util::StatusOr<std::unique_ptr<Serialization>> serialization2 =
      registry.SerializeKey<NoIdSerialization>(NoIdKey());
  ASSERT_THAT(serialization2, IsOk());

  registry.Reset();

  ASSERT_THAT(registry.ParseParameters(NoIdSerialization()).status(),
              StatusIs(absl::StatusCode::kNotFound));
  ASSERT_THAT(
      registry.SerializeParameters<NoIdSerialization>(NoIdParams()).status(),
      StatusIs(absl::StatusCode::kNotFound));
  ASSERT_THAT(registry.ParseKey(NoIdSerialization()).status(),
              StatusIs(absl::StatusCode::kNotFound));
  ASSERT_THAT(registry.SerializeKey<NoIdSerialization>(NoIdKey()).status(),
              StatusIs(absl::StatusCode::kNotFound));
}

TEST(MutableSerializationRegistryTest, GlobalInstance) {
  MutableSerializationRegistry::GlobalInstance().Reset();
  ParametersParserImpl<NoIdSerialization, NoIdParams> parser(kNoIdTypeUrl,
                                                             ParseNoIdParams);
  ASSERT_THAT(
      MutableSerializationRegistry::GlobalInstance().RegisterParametersParser(
          &parser),
      IsOk());

  util::StatusOr<std::unique_ptr<Parameters>> params =
      MutableSerializationRegistry::GlobalInstance().ParseParameters(
          NoIdSerialization());
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), IsFalse());
  EXPECT_THAT(std::type_index(typeid(**params)),
              std::type_index(typeid(NoIdParams)));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
