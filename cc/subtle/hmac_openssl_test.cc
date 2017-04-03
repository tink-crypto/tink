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

#include "cc/subtle/hmac_openssl.h"

#include "cc/mac.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "gtest/gtest.h"
#include "proto/common.pb.h"

using google::cloud::crypto::tink::HashType;

namespace cloud {
namespace crypto {
namespace tink {
namespace {

class HmacOpenSslTest : public ::testing::Test {
};

TEST_F(HmacOpenSslTest, testBasic) {
  auto hmac_result = HmacOpenSsl::New(HashType::SHA1, 16, "some key value");
  EXPECT_TRUE(hmac_result.ok()) << hmac_result.status();
  auto hmac = std::move(hmac_result.ValueOrDie());

  EXPECT_EQ(util::Status::UNKNOWN, hmac->ComputeMac("some data").status());
  EXPECT_EQ(util::Status::UNKNOWN, hmac->VerifyMac("mac value", "some data"));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
}  // namespace cloud


int main(int ac, char* av[]) {
  testing::InitGoogleTest(&ac, av);
  return RUN_ALL_TESTS();
}
