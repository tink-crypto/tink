// Copyright 2021 Google LLC
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

#include "tink/util/statusor.h"

#include <memory>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace util {
namespace {

using ::crypto::tink::test::IsOk;
using ::testing::Eq;
using ::testing::Not;
using ::testing::Pointee;

TEST(StatusOrTest, ConvertOkToAbsl) {
  StatusOr<int> instance = 1;

  absl::StatusOr<int> converted = instance;
  ASSERT_TRUE(converted.ok());
  EXPECT_EQ(*converted, 1);
}

TEST(StatusOrTest, ConvertErrorToAbsl) {
  #ifndef TINK_USE_ABSL_STATUS
  StatusOr<int> instance{
      Status(error::Code::INVALID_ARGUMENT, "Error message")};
  #else
  StatusOr<int> instance{
      Status(absl::StatusCode::kInvalidArgument, "Error message")};
  #endif

  absl::StatusOr<int> converted = instance;
  ASSERT_FALSE(converted.ok());
  EXPECT_EQ(converted.status().code(), absl::StatusCode::kInvalidArgument);
  EXPECT_EQ(converted.status().message(), "Error message");
}

TEST(StatusOrTest, ConvertUncopyableToAbsl) {
  StatusOr<std::unique_ptr<int>> instance = absl::make_unique<int>(1);

  absl::StatusOr<std::unique_ptr<int>> converted = std::move(instance);
  ASSERT_TRUE(converted.ok());
  EXPECT_THAT(*converted, Pointee(Eq(1)));
}

class NoDefaultConstructor {
 public:
  explicit NoDefaultConstructor(int i) {}

  NoDefaultConstructor() = delete;
  NoDefaultConstructor(const NoDefaultConstructor&) = default;
  NoDefaultConstructor& operator=(const NoDefaultConstructor&) =
      default;
  NoDefaultConstructor(NoDefaultConstructor&&) = default;
  NoDefaultConstructor& operator=(NoDefaultConstructor&&) = default;
};

// Tests that we can construct a StatusOr<T> even if there is no default
// constructor for T.
TEST(StatusOrTest, WithNoDefaultConstructor) {
  StatusOr<NoDefaultConstructor> value = NoDefaultConstructor(13);
  StatusOr<NoDefaultConstructor> error =
      Status(absl::StatusCode::kInvalidArgument, "Error message");
}

// This tests that when we assign to something which is previously an error,
// we create a new optional inside the StatusOr, and do not try to assign to
// the value of the optional instead.
TEST(StatusOrTest, AssignToErrorStatus) {
  StatusOr<std::string> error_initially =
      Status(absl::StatusCode::kInvalidArgument, "Error message");
  ASSERT_THAT(error_initially.status(), Not(IsOk()));
  StatusOr<std::string> ok_initially = std::string("Hi");
  error_initially = ok_initially;
  ASSERT_THAT(error_initially.status(), IsOk());
  ASSERT_THAT(error_initially.value(), Eq("Hi"));

#ifndef TINK_USE_ABSL_STATUSOR
  ASSERT_THAT(error_initially.ValueOrDie(), Eq("Hi"));
#endif
}

// This tests that when we assign to something which is previously an error and
// at the same time use the implicit conversion operator, we create a new
// optional inside the StatusOr, and do not try to assign to the value of the
// optional instead.
TEST(StatusOrTest, AssignToErrorStatusImplicitConvertible) {
  StatusOr<std::string> error_initially =
      Status(absl::StatusCode::kInvalidArgument, "Error message");
  ASSERT_THAT(error_initially.status(), Not(IsOk()));
  StatusOr<char const*> ok_initially = "Hi";
  error_initially = ok_initially;
  ASSERT_THAT(error_initially.status(), IsOk());
  ASSERT_THAT(error_initially.value(), Eq("Hi"));

#ifndef TINK_USE_ABSL_STATUSOR
  ASSERT_THAT(error_initially.ValueOrDie(), Eq("Hi"));
#endif
}

#ifndef TINK_USE_ABSL_STATUSOR
TEST(StatusOrTest, MoveOutMoveOnlyValueOrDie) {
  StatusOr<std::unique_ptr<int>> status_or_unique_ptr_int =
      absl::make_unique<int>(10);
  std::unique_ptr<int> ten = std::move(status_or_unique_ptr_int.ValueOrDie());
  ASSERT_THAT(*ten, Eq(10));
}
#endif

TEST(StatusOrTest, MoveOutMoveOnlyValue) {
  StatusOr<std::unique_ptr<int>> status_or_unique_ptr_int =
      absl::make_unique<int>(10);
  std::unique_ptr<int> ten = std::move(status_or_unique_ptr_int.value());
  ASSERT_THAT(*ten, Eq(10));
}

TEST(STatusOrTest, CallValueOnConst) {
  const StatusOr<int> const_status_or_ten = 10;
  ASSERT_THAT(const_status_or_ten.value(), Eq(10));
}

TEST(StatusOrTest, CallValueOnConstTemp) {
  const StatusOr<int> const_status_or_ten = 10;
  ASSERT_THAT(std::move(const_status_or_ten).value(), Eq(10));
}

TEST(StatusOrTest, TestValueConst) {
  const int kI = 4;
  const absl::StatusOr<int> thing(kI);
  EXPECT_EQ(kI, *thing);
}

TEST(StatusOrTest, TestPointerValue) {
  const int kI = 0;
  absl::StatusOr<const int*> thing(&kI);
  EXPECT_EQ(&kI, *thing);
}

TEST(StatusOrTest, TestPointerValueConst) {
  const int kI = 0;
  const absl::StatusOr<const int*> thing(&kI);
  EXPECT_EQ(&kI, *thing);
}

TEST(StatusOrTest, OperatorStarRefQualifiers) {
  static_assert(
      std::is_same<const int&,
                   decltype(*std::declval<const absl::StatusOr<int>&>())>(),
      "Unexpected ref-qualifiers");
  static_assert(
      std::is_same<int&, decltype(*std::declval<absl::StatusOr<int>&>())>(),
      "Unexpected ref-qualifiers");
  static_assert(
      std::is_same<const int&&,
                   decltype(*std::declval<const absl::StatusOr<int>&&>())>(),
      "Unexpected ref-qualifiers");
  static_assert(
      std::is_same<int&&, decltype(*std::declval<absl::StatusOr<int>&&>())>(),
      "Unexpected ref-qualifiers");
}

TEST(StatusOrTest, OperatorStar) {
  const util::StatusOr<std::string> const_lvalue("hello");
  EXPECT_EQ("hello", *const_lvalue);

  util::StatusOr<std::string> lvalue("hello");
  EXPECT_EQ("hello", *lvalue);

  // Note: Recall that std::move() is equivalent to a static_cast to an rvalue
  // reference type.
  const util::StatusOr<std::string> const_rvalue("hello");
  EXPECT_EQ("hello", *std::move(const_rvalue));  // NOLINT

  util::StatusOr<std::string> rvalue("hello");
  EXPECT_EQ("hello", *std::move(rvalue));
}

TEST(StatusOrTest, OperatorArrowQualifiers) {
  static_assert(
      std::is_same<
          const int*,
          decltype(std::declval<const util::StatusOr<int>&>().operator->())>(),
      "Unexpected qualifiers");
  static_assert(
      std::is_same<
          int*, decltype(std::declval<util::StatusOr<int>&>().operator->())>(),
      "Unexpected qualifiers");
  static_assert(
      std::is_same<
          const int*,
          decltype(std::declval<const util::StatusOr<int>&&>().operator->())>(),
      "Unexpected qualifiers");
  static_assert(
      std::is_same<
          int*, decltype(std::declval<util::StatusOr<int>&&>().operator->())>(),
      "Unexpected qualifiers");
}

TEST(StatusOrTest, OperatorArrow) {
  const util::StatusOr<std::string> const_lvalue("hello");
  EXPECT_EQ(std::string("hello"), const_lvalue->c_str());

  util::StatusOr<std::string> lvalue("hello");
  EXPECT_EQ(std::string("hello"), lvalue->c_str());
}

TEST(StatusOr, ElementType) {
  static_assert(std::is_same<absl::StatusOr<int>::value_type, int>(), "");
  static_assert(std::is_same<absl::StatusOr<char>::value_type, char>(), "");
}

}  // namespace

}  // namespace util
}  // namespace tink
}  // namespace crypto
