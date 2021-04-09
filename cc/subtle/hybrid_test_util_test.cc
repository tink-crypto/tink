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
#include "tink/subtle/hybrid_test_util.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {

namespace {

using ::crypto::tink::test::DummyHybridDecrypt;
using ::crypto::tink::test::DummyHybridEncrypt;
using ::crypto::tink::test::IsOk;
using ::testing::Not;

TEST(EncryptThenDecrypt, Basic) {
  DummyHybridEncrypt hybrid_encrypt("Encrypt1");
  DummyHybridDecrypt hybrid_decrypt("Encrypt1");
  EXPECT_THAT(HybridEncryptThenDecrypt(&hybrid_encrypt, &hybrid_decrypt,
                                       "plaintext", "aad"),
              IsOk());
}

TEST(EncryptThenDecrypt, Failing) {
  DummyHybridEncrypt hybrid_encrypt("Encrypt1");
  DummyHybridDecrypt hybrid_decrypt("Encrypt2");
  EXPECT_THAT(HybridEncryptThenDecrypt(&hybrid_encrypt, &hybrid_decrypt,
                                       "plaintext", "aad"),
              Not(IsOk()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
