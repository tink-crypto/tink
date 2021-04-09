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

#include "tink/util/secret_proto.h"

#include <utility>

#include "google/protobuf/util/message_differencer.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "proto/test_proto.pb.h"

namespace crypto {
namespace tink {
namespace util {
namespace {

using ::google::crypto::tink::NestedTestProto;
using ::google::crypto::tink::TestProto;
using ::google::protobuf::util::MessageDifferencer;

template <typename T>
class SecretProtoTest : public testing::Test {};

using MyTypes = ::testing::Types<NestedTestProto, TestProto>;
TYPED_TEST_SUITE(SecretProtoTest, MyTypes);

template <typename T>
T CreateProto();

template <>
TestProto CreateProto<TestProto>() {
  TestProto proto;
  proto.set_num(123);
  proto.set_str("Single proto");
  return proto;
}

template <>
NestedTestProto CreateProto<NestedTestProto>() {
  NestedTestProto proto;
  proto.mutable_a()->set_num(12);
  proto.mutable_a()->set_str("A proto");
  proto.mutable_b()->set_num(14);
  proto.mutable_b()->set_str("B proto");
  proto.set_num(42);
  proto.set_str("Main proto");
  return proto;
}

TYPED_TEST(SecretProtoTest, DefaultConstructor) {
  SecretProto<TypeParam> s;
  EXPECT_TRUE(MessageDifferencer::Equals(*s, TypeParam()));
}

TYPED_TEST(SecretProtoTest, Constructor) {
  TypeParam proto = CreateProto<TypeParam>();
  SecretProto<TypeParam> s(proto);
  EXPECT_TRUE(MessageDifferencer::Equals(*s, proto));
}

TYPED_TEST(SecretProtoTest, CopyConstructor) {
  TypeParam proto = CreateProto<TypeParam>();
  SecretProto<TypeParam> s(proto);
  SecretProto<TypeParam> t(s);
  EXPECT_TRUE(MessageDifferencer::Equals(*s, proto));
  EXPECT_TRUE(MessageDifferencer::Equals(*t, proto));
}

TYPED_TEST(SecretProtoTest, SourceDestroyedAfterCopyConstructor) {
  TypeParam proto = CreateProto<TypeParam>();
  auto s = absl::make_unique<SecretProto<TypeParam>>(proto);
  SecretProto<TypeParam> t(*s);
  EXPECT_TRUE(MessageDifferencer::Equals(**s, proto));
  EXPECT_TRUE(MessageDifferencer::Equals(*t, proto));
  // Test with source destroyed after the copy
  s.reset();
  EXPECT_TRUE(MessageDifferencer::Equals(*t, proto));
}

TYPED_TEST(SecretProtoTest, AssignmentOperator) {
  TypeParam proto = CreateProto<TypeParam>();
  SecretProto<TypeParam> t;
  {
    SecretProto<TypeParam> s(proto);
    t = s;
    EXPECT_TRUE(MessageDifferencer::Equals(*s, proto));
    EXPECT_TRUE(MessageDifferencer::Equals(*t, proto));
  }
  // Test with source destroyed after the copy
  EXPECT_TRUE(MessageDifferencer::Equals(*t, proto));
}

TYPED_TEST(SecretProtoTest, MoveConstructor) {
  TypeParam proto = CreateProto<TypeParam>();
  SecretProto<TypeParam> s(proto);
  SecretProto<TypeParam> t(std::move(s));
  EXPECT_TRUE(MessageDifferencer::Equals(*t, proto));
  // NOLINTNEXTLINE: bugprone-use-after-move
  EXPECT_TRUE(MessageDifferencer::Equals(*s, TypeParam()) ||
              MessageDifferencer::Equals(*s, proto));
}

TYPED_TEST(SecretProtoTest, MoveAssignment) {
  TypeParam proto = CreateProto<TypeParam>();
  SecretProto<TypeParam> t;
  {
    SecretProto<TypeParam> s(proto);
    t = std::move(s);
    EXPECT_TRUE(MessageDifferencer::Equals(*t, proto));
    // NOLINTNEXTLINE: bugprone-use-after-move
    EXPECT_TRUE(MessageDifferencer::Equals(*s, TypeParam()) ||
                MessageDifferencer::Equals(*s, proto));
  }
  // Test with source destroyed after the move
  EXPECT_TRUE(MessageDifferencer::Equals(*t, proto));
}

}  // namespace
}  // namespace util
}  // namespace tink
}  // namespace crypto
