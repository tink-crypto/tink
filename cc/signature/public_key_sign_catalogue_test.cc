// Copyright 2017 Google Inc.
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

#include "tink/signature/public_key_sign_catalogue.h"

#include "tink/catalogue.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "gtest/gtest.h"

namespace crypto {
namespace tink {
namespace {

class PublicKeySignCatalogueTest : public ::testing::Test {
};

TEST_F(PublicKeySignCatalogueTest, testBasic) {
  std::string key_type =
      "type.googleapis.com/google.crypto.tink.EcdsaPrivateKey";
  PublicKeySignCatalogue catalogue;

  {
    auto manager_result = catalogue.GetKeyManager(key_type, "PublicKeySign", 0);
    EXPECT_TRUE(manager_result.ok()) << manager_result.status();
    EXPECT_TRUE(manager_result.ValueOrDie()->DoesSupport(key_type));
  }

  {
    auto manager_result = catalogue.GetKeyManager(key_type, "pUblIckEySiGn", 0);
    EXPECT_TRUE(manager_result.ok()) << manager_result.status();
    EXPECT_TRUE(manager_result.ValueOrDie()->DoesSupport(key_type));
  }

  {
    auto manager_result = catalogue.GetKeyManager(key_type, "Aead", 0);
    EXPECT_FALSE(manager_result.ok());
    EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());
  }

  {
    auto manager_result = catalogue.GetKeyManager(key_type, "PublicKeySign", 1);
    EXPECT_FALSE(manager_result.ok());
    EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
