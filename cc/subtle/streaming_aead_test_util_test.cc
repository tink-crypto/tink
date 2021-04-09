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
#include "tink/subtle/streaming_aead_test_util.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {

using ::crypto::tink::test::DummyStreamingAead;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;

namespace {

TEST(EncryptThenDecrypt, Basic) {
  DummyStreamingAead streaming_aead("Aead 1");
  int ciphertext_offset = 0;
  EXPECT_THAT(EncryptThenDecrypt(&streaming_aead, &streaming_aead, "plaintext",
                                 "aad", ciphertext_offset),
              IsOk());
}

TEST(EncryptThenDecrypt, DifferentAeads) {
  DummyStreamingAead streaming_aead_1("Aead 1");
  DummyStreamingAead streaming_aead_2("Aead 2");
  int ciphertext_offset = 0;
  EXPECT_THAT(EncryptThenDecrypt(&streaming_aead_1, &streaming_aead_2,
                                 "plaintext", "aad", ciphertext_offset),
              StatusIs(util::error::INVALID_ARGUMENT));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
