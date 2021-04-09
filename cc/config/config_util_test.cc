// Copyright 2019 Google LLC
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

#include "tink/config/config_util.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

using ::testing::Eq;

namespace crypto {
namespace tink {

TEST(CreateKeyTypeEntry, Simple) {
  google::crypto::tink::KeyTypeEntry entry = CreateTinkKeyTypeEntry(
      "catalogue", "primitive_name", "key_proto_name", 12, true);
  EXPECT_THAT(entry.primitive_name(), Eq("primitive_name"));
  EXPECT_THAT(entry.type_url(),
              Eq("type.googleapis.com/google.crypto.tink.key_proto_name"));
  EXPECT_THAT(entry.key_manager_version(), Eq(12));
  EXPECT_THAT(entry.new_key_allowed(), Eq(true));
  EXPECT_THAT(entry.catalogue_name(), Eq("catalogue"));
}

}  // namespace tink
}  // namespace crypto
