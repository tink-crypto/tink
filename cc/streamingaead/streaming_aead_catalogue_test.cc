// Copyright 2019 Google Inc.
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

#include "tink/streamingaead/streaming_aead_catalogue.h"

#include "tink/catalogue.h"
#include "tink/streamingaead/streaming_aead_config.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "gtest/gtest.h"

namespace crypto {
namespace tink {
namespace {

class StreamingAeadCatalogueTest : public ::testing::Test {
};

TEST_F(StreamingAeadCatalogueTest, testBasic) {
  std::string key_types[] = {
    "type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey"};

  StreamingAeadCatalogue catalogue;
  {
    auto manager_result =
        catalogue.GetKeyManager("bad.key_type", "StreamingAead", 0);
    EXPECT_FALSE(manager_result.ok());
    EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());
  }
  for (const std::string& key_type : key_types) {
    {
      auto manager_result =
          catalogue.GetKeyManager(key_type, "StreamingAead", 0);
      EXPECT_TRUE(manager_result.ok()) << manager_result.status();
      EXPECT_TRUE(manager_result.ValueOrDie()->DoesSupport(key_type));
    }

    {
      auto manager_result =
          catalogue.GetKeyManager(key_type, "streamingaead", 0);
      EXPECT_TRUE(manager_result.ok()) << manager_result.status();
      EXPECT_TRUE(manager_result.ValueOrDie()->DoesSupport(key_type));
    }

    {
      auto manager_result = catalogue.GetKeyManager(key_type, "Mac", 0);
      EXPECT_FALSE(manager_result.ok());
      EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());
    }

    {
      auto manager_result =
          catalogue.GetKeyManager(key_type, "StreamingAead", 1);
      EXPECT_FALSE(manager_result.ok());
      EXPECT_EQ(util::error::NOT_FOUND, manager_result.status().error_code());
    }
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
