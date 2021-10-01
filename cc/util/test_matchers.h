// Copyright 2018 Google Inc.
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

#ifndef TINK_UTIL_TEST_MATCHERS_H_
#define TINK_UTIL_TEST_MATCHERS_H_

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace test {
namespace internal {

////////////////////////////////////////////////////////////
// Implementation of IsOkAndHolds().

// Monomorphic implementation of matcher IsOkAndHolds(m).  StatusOrType is a
// reference to StatusOr<T>.
template <typename StatusOrType>
class IsOkAndHoldsMatcherImpl
    : public ::testing::MatcherInterface<StatusOrType> {
 public:
  using value_type = typename std::remove_reference<StatusOrType>::type::type;

  template <typename InnerMatcher>
  explicit IsOkAndHoldsMatcherImpl(InnerMatcher&& inner_matcher)
      : inner_matcher_(::testing::SafeMatcherCast<const value_type&>(
            std::forward<InnerMatcher>(inner_matcher))) {}

  void DescribeTo(std::ostream* os) const override {
    *os << "is OK and has a value that ";
    inner_matcher_.DescribeTo(os);
  }

  void DescribeNegationTo(std::ostream* os) const override {
    *os << "isn't OK or has a value that ";
    inner_matcher_.DescribeNegationTo(os);
  }

  bool MatchAndExplain(
      StatusOrType actual_value,
      ::testing::MatchResultListener* result_listener) const override {
    if (!actual_value.ok()) {
      *result_listener << "which has status " << actual_value.status();
      return false;
    }

    ::testing::StringMatchResultListener inner_listener;
    const bool matches = inner_matcher_.MatchAndExplain(
        actual_value.ValueOrDie(), &inner_listener);
    const std::string inner_explanation = inner_listener.str();
    if (!inner_explanation.empty()) {
      *result_listener << "which contains value "
                       << ::testing::PrintToString(actual_value.ValueOrDie())
                       << ", " << inner_explanation;
    }
    return matches;
  }

 private:
  const ::testing::Matcher<const value_type&> inner_matcher_;
};

// Implements IsOkAndHolds(m) as a polymorphic matcher.
template <typename InnerMatcher>
class IsOkAndHoldsMatcher {
 public:
  explicit IsOkAndHoldsMatcher(InnerMatcher inner_matcher)
      : inner_matcher_(std::move(inner_matcher)) {}

  // Converts this polymorphic matcher to a monomorphic matcher of the
  // given type.  StatusOrType can be either StatusOr<T> or a
  // reference to StatusOr<T>.
  template <typename StatusOrType>
  operator ::testing::Matcher<StatusOrType>() const {  // NOLINT
    return ::testing::Matcher<StatusOrType>(
        new IsOkAndHoldsMatcherImpl<const StatusOrType&>(inner_matcher_));
  }

 private:
  const InnerMatcher inner_matcher_;
};
}  // namespace internal

// Matches a util::StatusOk() value.
// This is better than EXPECT_TRUE(status.ok())
// because the error message is a part of the failure messsage.
MATCHER(IsOk, "is a Status with an OK value") {
  if (arg.ok()) {
    return true;
  }
  *result_listener << arg.ToString();
  return false;
}

// Returns a gMock matcher that matches a StatusOr<> whose status is
// OK and whose value matches the inner matcher.
template <typename InnerMatcher>
internal::IsOkAndHoldsMatcher<typename std::decay<InnerMatcher>::type>
IsOkAndHolds(InnerMatcher&& inner_matcher) {
  return internal::IsOkAndHoldsMatcher<typename std::decay<InnerMatcher>::type>(
      std::forward<InnerMatcher>(inner_matcher));
}

// Matches a Status with the specified 'code' as error_code().
// TODO(lizatretyakova): remove the static_cast and fix the comment above to
// use code() after all StatusIs usages are migrated to use absl::StatusCode.
MATCHER_P(StatusIs, code,
          "is a Status with a " + util::ErrorCodeString(code) + " code") {
  if (arg.code() == static_cast<absl::StatusCode>(code)) {
    return true;
  }
  *result_listener << ::testing::PrintToString(arg);
  return false;
}

// Matches a Status whose error_code() equals 'code', and whose
// error_message() matches 'message_macher'.
// TODO(lizatretyakova): remove the static_cast and fix the comment above to
// use code() after all StatusIs usages are migrated to use absl::StatusCode.
MATCHER_P2(StatusIs, code, message_matcher, "") {
  return (arg.code() == static_cast<absl::StatusCode>(code)) &&
         testing::Matches(message_matcher)(arg.error_message());
}

// Matches a Keyset::Key with `key`.
MATCHER_P(EqualsKey, key, "is equals to the expected key") {
  if (arg.key_id() == key.key_id() && arg.status() == key.status() &&
         arg.output_prefix_type() == key.output_prefix_type() &&
         arg.key_data().type_url() == key.key_data().type_url() &&
         arg.key_data().key_material_type() ==
             key.key_data().key_material_type() &&
         arg.key_data().value() == key.key_data().value()) {
    return true;
  }
  *result_listener << arg.DebugString();
  return false;
}

}  // namespace test
}  // namespace tink
}  // namespace crypto

#endif  // TINK_UTIL_TEST_MATCHERS_H_
