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

#include "tink/internal/serialization_registry.h"

#include <memory>
#include <string_view>
#include <typeindex>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/insecure_secret_key_access.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_test_util.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::IsFalse;
using ::testing::IsTrue;

TEST(SerializationRegistryTest, ParseParameters) {
  SerializationRegistry::Builder builder;
  ParametersParserImpl<NoIdSerialization, NoIdParams> parser1(kNoIdTypeUrl,
                                                              ParseNoIdParams);
  ParametersParserImpl<IdParamsSerialization, IdParams> parser2(kIdTypeUrl,
                                                                ParseIdParams);
  ASSERT_THAT(builder.RegisterParametersParser(&parser1), IsOk());
  ASSERT_THAT(builder.RegisterParametersParser(&parser2), IsOk());

  SerializationRegistry registry = builder.Build();

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

TEST(SerializationRegistryTest, ParseParametersWithoutRegistration) {
  SerializationRegistry::Builder builder;
  SerializationRegistry registry = builder.Build();

  ASSERT_THAT(registry.ParseParameters(NoIdSerialization()).status(),
              StatusIs(absl::StatusCode::kNotFound));
}

TEST(SerializationRegistryTest, RegisterSameParametersParser) {
  SerializationRegistry::Builder builder;
  ParametersParserImpl<NoIdSerialization, NoIdParams> parser(kNoIdTypeUrl,
                                                             ParseNoIdParams);

  EXPECT_THAT(builder.RegisterParametersParser(&parser), IsOk());
  EXPECT_THAT(builder.RegisterParametersParser(&parser), IsOk());
}

TEST(SerializationRegistryTest,
     RegisterDifferentParametersParserWithSameIndex) {
  SerializationRegistry::Builder builder;
  ParametersParserImpl<NoIdSerialization, NoIdParams> parser1(kNoIdTypeUrl,
                                                              ParseNoIdParams);
  ParametersParserImpl<NoIdSerialization, NoIdParams> parser2(kNoIdTypeUrl,
                                                              ParseNoIdParams);

  EXPECT_THAT(builder.RegisterParametersParser(&parser1), IsOk());
  EXPECT_THAT(builder.RegisterParametersParser(&parser2),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

TEST(SerializationRegistryTest, SerializeParameters) {
  SerializationRegistry::Builder builder;
  ParametersSerializerImpl<NoIdParams, NoIdSerialization> serializer1(
      kNoIdTypeUrl, SerializeNoIdParams);
  ParametersSerializerImpl<IdParams, IdParamsSerialization> serializer2(
      kIdTypeUrl, SerializeIdParams);
  ASSERT_THAT(builder.RegisterParametersSerializer(&serializer1), IsOk());
  ASSERT_THAT(builder.RegisterParametersSerializer(&serializer2), IsOk());

  SerializationRegistry registry = builder.Build();

  util::StatusOr<std::unique_ptr<Serialization>> serialization1 =
      registry.SerializeParameters<NoIdSerialization>(NoIdParams());
  ASSERT_THAT(serialization1, IsOk());
  EXPECT_THAT((*serialization1)->ObjectIdentifier(), Eq(kNoIdTypeUrl));

  util::StatusOr<std::unique_ptr<Serialization>> serialization2 =
      registry.SerializeParameters<IdParamsSerialization>(IdParams());
  ASSERT_THAT(serialization2, IsOk());
  EXPECT_THAT((*serialization2)->ObjectIdentifier(), Eq(kIdTypeUrl));
}

TEST(SerializationRegistryTest, SerializeParametersWithoutRegistration) {
  SerializationRegistry::Builder builder;
  SerializationRegistry registry = builder.Build();

  ASSERT_THAT(
      registry.SerializeParameters<NoIdSerialization>(NoIdParams()).status(),
      StatusIs(absl::StatusCode::kNotFound));
}

TEST(SerializationRegistryTest, RegisterSameParametersSerializer) {
  SerializationRegistry::Builder builder;
  ParametersSerializerImpl<NoIdParams, NoIdSerialization> serializer(
      kNoIdTypeUrl, SerializeNoIdParams);

  EXPECT_THAT(builder.RegisterParametersSerializer(&serializer), IsOk());
  EXPECT_THAT(builder.RegisterParametersSerializer(&serializer), IsOk());
}

TEST(SerializationRegistryTest,
     RegisterDifferentParametersSerializerWithSameIndex) {
  SerializationRegistry::Builder builder;
  ParametersSerializerImpl<NoIdParams, NoIdSerialization> serializer1(
      kNoIdTypeUrl, SerializeNoIdParams);
  ParametersSerializerImpl<NoIdParams, NoIdSerialization> serializer2(
      kNoIdTypeUrl, SerializeNoIdParams);

  EXPECT_THAT(builder.RegisterParametersSerializer(&serializer1), IsOk());
  EXPECT_THAT(builder.RegisterParametersSerializer(&serializer2),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

TEST(SerializationRegistryTest, ParseKey) {
  SerializationRegistry::Builder builder;
  KeyParserImpl<NoIdSerialization, NoIdKey> parser1(kNoIdTypeUrl, ParseNoIdKey);
  KeyParserImpl<IdKeySerialization, IdKey> parser2(kIdTypeUrl, ParseIdKey);
  ASSERT_THAT(builder.RegisterKeyParser(&parser1), IsOk());
  ASSERT_THAT(builder.RegisterKeyParser(&parser2), IsOk());

  SerializationRegistry registry = builder.Build();

  util::StatusOr<std::unique_ptr<Key>> no_id_key =
      registry.ParseKey(NoIdSerialization(), InsecureSecretKeyAccess::Get());
  ASSERT_THAT(no_id_key, IsOk());
  EXPECT_THAT(std::type_index(typeid(**no_id_key)),
              std::type_index(typeid(NoIdKey)));

  util::StatusOr<std::unique_ptr<Key>> id_key = registry.ParseKey(
      IdKeySerialization(/*id=*/123), InsecureSecretKeyAccess::Get());
  ASSERT_THAT(id_key, IsOk());
  EXPECT_THAT(std::type_index(typeid(**id_key)),
              std::type_index(typeid(IdKey)));
  EXPECT_THAT((*id_key)->GetIdRequirement(), Eq(123));
}

TEST(SerializationRegistryTest, ParseKeyNoSecretAccess) {
  SerializationRegistry::Builder builder;
  KeyParserImpl<NoIdSerialization, NoIdKey> parser(kNoIdTypeUrl, ParseNoIdKey);
  ASSERT_THAT(builder.RegisterKeyParser(&parser), IsOk());

  SerializationRegistry registry = builder.Build();

  util::StatusOr<std::unique_ptr<Key>> no_id_public_key =
      registry.ParseKey(NoIdSerialization(), absl::nullopt);
  ASSERT_THAT(no_id_public_key, IsOk());
  EXPECT_THAT(std::type_index(typeid(**no_id_public_key)),
              std::type_index(typeid(NoIdKey)));
}

TEST(SerializationRegistryTest, ParseKeyWithoutRegistration) {
  SerializationRegistry::Builder builder;
  SerializationRegistry registry = builder.Build();

  ASSERT_THAT(
      registry.ParseKey(NoIdSerialization(), InsecureSecretKeyAccess::Get())
          .status(),
      StatusIs(absl::StatusCode::kNotFound));
}

TEST(SerializationRegistryTest, RegisterSameKeyParser) {
  SerializationRegistry::Builder builder;
  KeyParserImpl<NoIdSerialization, NoIdKey> parser(kNoIdTypeUrl, ParseNoIdKey);

  EXPECT_THAT(builder.RegisterKeyParser(&parser), IsOk());
  EXPECT_THAT(builder.RegisterKeyParser(&parser), IsOk());
}

TEST(SerializationRegistryTest, RegisterDifferentKeyParserWithSameIndex) {
  SerializationRegistry::Builder builder;
  KeyParserImpl<NoIdSerialization, NoIdKey> parser1(kNoIdTypeUrl, ParseNoIdKey);
  KeyParserImpl<NoIdSerialization, NoIdKey> parser2(kNoIdTypeUrl, ParseNoIdKey);

  EXPECT_THAT(builder.RegisterKeyParser(&parser1), IsOk());
  EXPECT_THAT(builder.RegisterKeyParser(&parser2),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

TEST(SerializationRegistryTest, SerializeKey) {
  SerializationRegistry::Builder builder;
  KeySerializerImpl<NoIdKey, NoIdSerialization> serializer1(SerializeNoIdKey);
  KeySerializerImpl<IdKey, IdKeySerialization> serializer2(SerializeIdKey);
  ASSERT_THAT(builder.RegisterKeySerializer(&serializer1), IsOk());
  ASSERT_THAT(builder.RegisterKeySerializer(&serializer2), IsOk());

  SerializationRegistry registry = builder.Build();

  util::StatusOr<std::unique_ptr<Serialization>> serialization1 =
      registry.SerializeKey<NoIdSerialization>(NoIdKey(),
                                               InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization1, IsOk());
  EXPECT_THAT((*serialization1)->ObjectIdentifier(), Eq(kNoIdTypeUrl));

  util::StatusOr<std::unique_ptr<Serialization>> serialization2 =
      registry.SerializeKey<IdKeySerialization>(IdKey(123),
                                                InsecureSecretKeyAccess::Get());
  ASSERT_THAT(serialization2, IsOk());
  EXPECT_THAT((*serialization2)->ObjectIdentifier(), Eq(kIdTypeUrl));
}

TEST(SerializationRegistryTest, SerializeKeyNoSecretAccess) {
  SerializationRegistry::Builder builder;
  KeySerializerImpl<NoIdKey, NoIdSerialization> serializer(SerializeNoIdKey);
  ASSERT_THAT(builder.RegisterKeySerializer(&serializer), IsOk());

  SerializationRegistry registry = builder.Build();

  util::StatusOr<std::unique_ptr<Serialization>> serialization =
      registry.SerializeKey<NoIdSerialization>(NoIdKey(),
                                               absl::nullopt);
  ASSERT_THAT(serialization, IsOk());
  EXPECT_THAT((*serialization)->ObjectIdentifier(), Eq(kNoIdTypeUrl));
}

TEST(SerializationRegistryTest, SerializeKeyWithoutRegistration) {
  SerializationRegistry::Builder builder;
  SerializationRegistry registry = builder.Build();

  ASSERT_THAT(registry
                  .SerializeKey<NoIdSerialization>(
                      NoIdKey(), InsecureSecretKeyAccess::Get())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
}

TEST(SerializationRegistryTest, RegisterSameKeySerializer) {
  SerializationRegistry::Builder builder;
  KeySerializerImpl<NoIdKey, NoIdSerialization> serializer(SerializeNoIdKey);

  EXPECT_THAT(builder.RegisterKeySerializer(&serializer), IsOk());
  EXPECT_THAT(builder.RegisterKeySerializer(&serializer), IsOk());
}

TEST(SerializationRegistryTest, RegisterDifferentKeySerializerWithSameIndex) {
  SerializationRegistry::Builder builder;
  KeySerializerImpl<NoIdKey, NoIdSerialization> serializer1(SerializeNoIdKey);
  KeySerializerImpl<NoIdKey, NoIdSerialization> serializer2(SerializeNoIdKey);

  EXPECT_THAT(builder.RegisterKeySerializer(&serializer1), IsOk());
  EXPECT_THAT(builder.RegisterKeySerializer(&serializer2),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

TEST(SerializationRegistryTest, BuiltFromAnotherRegistry) {
  SerializationRegistry::Builder builder1;
  ParametersParserImpl<NoIdSerialization, NoIdParams> parser1(kNoIdTypeUrl,
                                                              ParseNoIdParams);
  ParametersSerializerImpl<NoIdParams, NoIdSerialization> serializer1(
      kNoIdTypeUrl, SerializeNoIdParams);
  ASSERT_THAT(builder1.RegisterParametersParser(&parser1), IsOk());
  ASSERT_THAT(builder1.RegisterParametersSerializer(&serializer1), IsOk());

  SerializationRegistry registry1 = builder1.Build();
  SerializationRegistry::Builder builder2(registry1);

  KeyParserImpl<NoIdSerialization, NoIdKey> parser2(kNoIdTypeUrl, ParseNoIdKey);
  KeySerializerImpl<NoIdKey, NoIdSerialization> serializer2(SerializeNoIdKey);
  ASSERT_THAT(builder2.RegisterKeyParser(&parser2), IsOk());
  ASSERT_THAT(builder2.RegisterKeySerializer(&serializer2), IsOk());

  SerializationRegistry registry2 = builder2.Build();

  util::StatusOr<std::unique_ptr<Parameters>> params =
      registry2.ParseParameters(NoIdSerialization());
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), IsFalse());
  EXPECT_THAT(std::type_index(typeid(**params)),
              std::type_index(typeid(NoIdParams)));

  util::StatusOr<std::unique_ptr<Serialization>> params_serialization =
      registry2.SerializeParameters<NoIdSerialization>(NoIdParams());
  ASSERT_THAT(params_serialization, IsOk());
  EXPECT_THAT((*params_serialization)->ObjectIdentifier(), Eq(kNoIdTypeUrl));

  util::StatusOr<std::unique_ptr<Key>> key =
      registry2.ParseKey(NoIdSerialization(), InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(std::type_index(typeid(**key)), std::type_index(typeid(NoIdKey)));

  util::StatusOr<std::unique_ptr<Serialization>> key_serialization =
      registry2.SerializeKey<NoIdSerialization>(NoIdKey(),
                                                InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key_serialization, IsOk());
  EXPECT_THAT((*key_serialization)->ObjectIdentifier(), Eq(kNoIdTypeUrl));
}

TEST(SerializationRegistryTest, RegistryCopy) {
  SerializationRegistry::Builder builder;
  ParametersParserImpl<NoIdSerialization, NoIdParams> parser1(kNoIdTypeUrl,
                                                              ParseNoIdParams);
  ParametersSerializerImpl<NoIdParams, NoIdSerialization> serializer1(
      kNoIdTypeUrl, SerializeNoIdParams);
  KeyParserImpl<NoIdSerialization, NoIdKey> parser2(kNoIdTypeUrl, ParseNoIdKey);
  KeySerializerImpl<NoIdKey, NoIdSerialization> serializer2(SerializeNoIdKey);
  ASSERT_THAT(builder.RegisterParametersParser(&parser1), IsOk());
  ASSERT_THAT(builder.RegisterParametersSerializer(&serializer1), IsOk());
  ASSERT_THAT(builder.RegisterKeyParser(&parser2), IsOk());
  ASSERT_THAT(builder.RegisterKeySerializer(&serializer2), IsOk());

  SerializationRegistry registry1 = builder.Build();
  SerializationRegistry registry2 = registry1;

  util::StatusOr<std::unique_ptr<Parameters>> params =
      registry2.ParseParameters(NoIdSerialization());
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), IsFalse());
  EXPECT_THAT(std::type_index(typeid(**params)),
              std::type_index(typeid(NoIdParams)));

  util::StatusOr<std::unique_ptr<Serialization>> params_serialization =
      registry2.SerializeParameters<NoIdSerialization>(NoIdParams());
  ASSERT_THAT(params_serialization, IsOk());
  EXPECT_THAT((*params_serialization)->ObjectIdentifier(), Eq(kNoIdTypeUrl));

  util::StatusOr<std::unique_ptr<Key>> key =
      registry2.ParseKey(NoIdSerialization(), InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(std::type_index(typeid(**key)), std::type_index(typeid(NoIdKey)));

  util::StatusOr<std::unique_ptr<Serialization>> key_serialization =
      registry2.SerializeKey<NoIdSerialization>(NoIdKey(),
                                                InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key_serialization, IsOk());
  EXPECT_THAT((*key_serialization)->ObjectIdentifier(), Eq(kNoIdTypeUrl));
}

TEST(SerializationRegistryTest, RegistryMove) {
  SerializationRegistry::Builder builder;
  ParametersParserImpl<NoIdSerialization, NoIdParams> parser1(kNoIdTypeUrl,
                                                              ParseNoIdParams);
  ParametersSerializerImpl<NoIdParams, NoIdSerialization> serializer1(
      kNoIdTypeUrl, SerializeNoIdParams);
  KeyParserImpl<NoIdSerialization, NoIdKey> parser2(kNoIdTypeUrl, ParseNoIdKey);
  KeySerializerImpl<NoIdKey, NoIdSerialization> serializer2(SerializeNoIdKey);
  ASSERT_THAT(builder.RegisterParametersParser(&parser1), IsOk());
  ASSERT_THAT(builder.RegisterParametersSerializer(&serializer1), IsOk());
  ASSERT_THAT(builder.RegisterKeyParser(&parser2), IsOk());
  ASSERT_THAT(builder.RegisterKeySerializer(&serializer2), IsOk());

  SerializationRegistry registry1 = builder.Build();
  SerializationRegistry registry2 = std::move(registry1);

  util::StatusOr<std::unique_ptr<Parameters>> params =
      registry2.ParseParameters(NoIdSerialization());
  ASSERT_THAT(params, IsOk());
  EXPECT_THAT((*params)->HasIdRequirement(), IsFalse());
  EXPECT_THAT(std::type_index(typeid(**params)),
              std::type_index(typeid(NoIdParams)));

  util::StatusOr<std::unique_ptr<Serialization>> params_serialization =
      registry2.SerializeParameters<NoIdSerialization>(NoIdParams());
  ASSERT_THAT(params_serialization, IsOk());
  EXPECT_THAT((*params_serialization)->ObjectIdentifier(), Eq(kNoIdTypeUrl));

  util::StatusOr<std::unique_ptr<Key>> key =
      registry2.ParseKey(NoIdSerialization(), InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key, IsOk());
  EXPECT_THAT(std::type_index(typeid(**key)), std::type_index(typeid(NoIdKey)));

  util::StatusOr<std::unique_ptr<Serialization>> key_serialization =
      registry2.SerializeKey<NoIdSerialization>(NoIdKey(),
                                                InsecureSecretKeyAccess::Get());
  ASSERT_THAT(key_serialization, IsOk());
  EXPECT_THAT((*key_serialization)->ObjectIdentifier(), Eq(kNoIdTypeUrl));
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto
