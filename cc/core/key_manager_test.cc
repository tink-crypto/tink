// Copyright 2018 Google Inc.
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
#include "tink/key_manager.h"

#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "proto/empty.pb.h"

namespace crypto {
namespace tink {

namespace {

using ::crypto::tink::test::StatusIs;

TEST(AlwaysFailingFactoryTest, NewKeyFromProtoLite) {
  std::unique_ptr<KeyFactory> factory = KeyFactory::AlwaysFailingFactory(
      util::Status(absl::StatusCode::kAlreadyExists, ""));
  google::crypto::tink::Empty empty_proto;
  EXPECT_THAT(factory->NewKey(empty_proto).status(),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

TEST(AlwaysFailingFactoryTest, NewKeyFromStringView) {
  std::unique_ptr<KeyFactory> factory = KeyFactory::AlwaysFailingFactory(
      util::Status(absl::StatusCode::kAlreadyExists, ""));
  EXPECT_THAT(factory->NewKey("").status(),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

TEST(AlwaysFailingFactoryTest, NewKeyData) {
  std::unique_ptr<KeyFactory> factory = KeyFactory::AlwaysFailingFactory(
      util::Status(absl::StatusCode::kAlreadyExists, ""));
  EXPECT_THAT(factory->NewKeyData("").status(),
              StatusIs(absl::StatusCode::kAlreadyExists));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
