// Copyright 2020 Google LLC
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
#include "tink/internal/keyset_wrapper_impl.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "tink/primitive_set.h"
#include "tink/primitive_wrapper.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

namespace {

using ::crypto::tink::test::AddKeyData;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::google::crypto::tink::Keyset;
using ::testing::HasSubstr;
using ::testing::Not;
using ::testing::Pair;
using ::testing::Pointee;
using ::testing::UnorderedElementsAre;

using InputPrimitive = std::string;
using OutputPrimitive = std::vector<std::pair<int, std::string>>;

// This "Wrapper" wraps primitives of type std::string into primitives of type
// std::vector<int, std::string> simply by returning pairs {key_id, string}.
// It appends " (primary)" to the string for the primary id.
class Wrapper : public PrimitiveWrapper<InputPrimitive, OutputPrimitive> {
 public:
  crypto::tink::util::StatusOr<std::unique_ptr<OutputPrimitive>> Wrap(
      std::unique_ptr<PrimitiveSet<InputPrimitive>> primitive_set)
      const override {
    auto result = absl::make_unique<OutputPrimitive>();
    for (const auto* entry : primitive_set->get_all()) {
      (*result).push_back(
          std::make_pair(entry->get_key_id(), entry->get_primitive()));
      if (entry->get_key_id() == primitive_set->get_primary()->get_key_id()) {
        result->back().second.append(" (primary)");
      }
    }
    return std::move(result);
  }
};

crypto::tink::util::StatusOr<std::unique_ptr<InputPrimitive>> CreateIn(
    const google::crypto::tink::KeyData& key_data) {
  if (absl::StartsWith(key_data.type_url(), "error:")) {
    return crypto::tink::util::Status(absl::StatusCode::kInvalidArgument,
                                      key_data.type_url());
  } else {
    return absl::make_unique<InputPrimitive>(key_data.type_url());
  }
}

google::crypto::tink::KeyData OnlyTypeUrlKeyData(absl::string_view type_url) {
  google::crypto::tink::KeyData result;
  result.set_type_url(std::string(type_url));
  return result;
}

google::crypto::tink::Keyset CreateKeyset(
    const std::vector<std::pair<int, std::string>>& keydata) {
  google::crypto::tink::Keyset keyset;
  for (const auto& pair : keydata) {
    AddKeyData(OnlyTypeUrlKeyData(pair.second), pair.first,
               google::crypto::tink::OutputPrefixType::TINK,
               google::crypto::tink::KeyStatusType::ENABLED, &keyset);
  }
  return keyset;
}

TEST(KeysetWrapperImplTest, Basic) {
  Wrapper wrapper;
  auto wrapper_or =
      absl::make_unique<KeysetWrapperImpl<InputPrimitive, OutputPrimitive>>(
          &wrapper, &CreateIn);
  std::vector<std::pair<int, std::string>> keydata = {
      {111, "one"}, {222, "two"}, {333, "three"}};
  google::crypto::tink::Keyset keyset = CreateKeyset(keydata);
  keyset.set_primary_key_id(222);

  util::StatusOr<std::unique_ptr<OutputPrimitive>> wrapped =
      wrapper_or->Wrap(keyset, /*annotations=*/{});

  ASSERT_THAT(wrapped.status(), IsOk());
  ASSERT_THAT(*wrapped.value(),
              UnorderedElementsAre(Pair(111, "one"), Pair(222, "two (primary)"),
                                   Pair(333, "three")));
}

TEST(KeysetWrapperImplTest, FailingGetPrimitive) {
  Wrapper wrapper;
  auto wrapper_or =
      absl::make_unique<KeysetWrapperImpl<InputPrimitive, OutputPrimitive>>(
          &wrapper, &CreateIn);
  std::vector<std::pair<int, std::string>> keydata = {{1, "ok:one"},
                                                      {2, "error:two"}};
  google::crypto::tink::Keyset keyset = CreateKeyset(keydata);
  keyset.set_primary_key_id(1);

  util::StatusOr<std::unique_ptr<OutputPrimitive>> wrapped =
      wrapper_or->Wrap(keyset, /*annotations=*/{});

  ASSERT_THAT(wrapped.status(), Not(IsOk()));
  ASSERT_THAT(std::string(wrapped.status().message()), HasSubstr("error:two"));
}

// This test checks that validate keyset is called. We simply pass an empty
// keyset.
TEST(KeysetWrapperImplTest, ValidatesKeyset) {
  Wrapper wrapper;
  auto wrapper_or =
      absl::make_unique<KeysetWrapperImpl<InputPrimitive, OutputPrimitive>>(
          &wrapper, &CreateIn);
  util::StatusOr<std::unique_ptr<OutputPrimitive>> wrapped =
      wrapper_or->Wrap(google::crypto::tink::Keyset(), /*annotations=*/{});

  ASSERT_THAT(wrapped.status(), Not(IsOk()));
}

// This test checks that only enabled keys are used to create the primitive set.
TEST(KeysetWrapperImplTest, OnlyEnabled) {
  Wrapper wrapper;
  auto wrapper_or =
      absl::make_unique<KeysetWrapperImpl<InputPrimitive, OutputPrimitive>>(
          &wrapper, &CreateIn);
  std::vector<std::pair<int, std::string>> keydata = {
      {111, "one"}, {222, "two"}, {333, "three"}, {444, "four"}};
  google::crypto::tink::Keyset keyset = CreateKeyset(keydata);
  keyset.set_primary_key_id(222);
  // KeyId 333 is index 2.
  keyset.mutable_key(2)->set_status(google::crypto::tink::DISABLED);
  util::StatusOr<std::unique_ptr<OutputPrimitive>> wrapped =
      wrapper_or->Wrap(keyset, /*annotations=*/{});

  ASSERT_THAT(wrapped.status(), IsOk());
  ASSERT_THAT(*wrapped.value(),
              UnorderedElementsAre(Pair(111, "one"), Pair(222, "two (primary)"),
                                   Pair(444, "four")));
}

// Mock PrimitiveWrapper with input primitive I and output primitive O.
template <class I, class O>
class MockWrapper : public PrimitiveWrapper<I, O> {
 public:
  MOCK_METHOD(util::StatusOr<std::unique_ptr<O>>, Wrap,
              (std::unique_ptr<PrimitiveSet<I>> primitive_set),
              (const, override));
};

// Returns a valid output primitive.
std::unique_ptr<OutputPrimitive> GetOutputPrimitiveForTesting() {
  auto output_primitive = absl::make_unique<OutputPrimitive>();
  output_primitive->push_back({111, "one"});
  output_primitive->push_back({222, "two (primary)"});
  output_primitive->push_back({333, "three"});
  output_primitive->push_back({444, "four"});
  return output_primitive;
}

// Tests that annotations are correctly passed on to the generated PrimitiveSet.
TEST(KeysetWrapperImplTest, WrapWithAnnotationCorrectlyWrittenToPrimitiveSet) {
  auto wrapper = MockWrapper<InputPrimitive, OutputPrimitive>();
  auto keyset_wrapper =
      absl::make_unique<KeysetWrapperImpl<InputPrimitive, OutputPrimitive>>(
          &wrapper, CreateIn);
  Keyset keyset = CreateKeyset(
      /*keydata=*/{{111, "one"}, {222, "two"}, {333, "three"}, {444, "four"}});
  keyset.set_primary_key_id(222);
  const absl::flat_hash_map<std::string, std::string> kExpectedAnnotations = {
      {"key1", "value1"}, {"key2", "value2"}};

  absl::flat_hash_map<std::string, std::string> generated_annotations;
  EXPECT_CALL(wrapper, Wrap(testing::_))
      .WillOnce(
          [&generated_annotations](std::unique_ptr<PrimitiveSet<InputPrimitive>>
                                       generated_primitive_set) {
            // We are interested to check if the annotations are what we
            // expected, so we copy them to `generated_annotations`.
            generated_annotations = generated_primitive_set->get_annotations();
            // Return a valid output primitive.
            return GetOutputPrimitiveForTesting();
          });

  util::StatusOr<std::unique_ptr<OutputPrimitive>> wrapped_primitive =
      keyset_wrapper->Wrap(keyset, kExpectedAnnotations);

  EXPECT_EQ(generated_annotations, kExpectedAnnotations);
  EXPECT_THAT(wrapped_primitive,
              IsOkAndHolds(Pointee(UnorderedElementsAre(
                  Pair(111, "one"), Pair(222, "two (primary)"),
                  Pair(333, "three"), Pair(444, "four")))));
}

}  // namespace

}  // namespace internal
}  // namespace tink
}  // namespace crypto
