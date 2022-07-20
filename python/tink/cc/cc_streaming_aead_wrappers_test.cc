// Copyright 2020 Google LLC
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

#include "tink/cc/cc_streaming_aead_wrappers.h"

#include <utility>

#include "gtest/gtest.h"
#include "tink/cc/test_util.h"

namespace crypto {
namespace tink {
namespace {

using crypto::tink::test::DummyStreamingAead;

TEST(CcStreamingAeadWrappersTest, BasicNewCcEncryptingStream) {
  DummyStreamingAead dummy_saead = DummyStreamingAead("Some streaming AEAD");
  std::unique_ptr<PythonFileObjectAdapter> output =
      absl::make_unique<test::TestWritableObject>();

  auto result =
      NewCcEncryptingStream(&dummy_saead, "associated data", std::move(output));

  EXPECT_TRUE(result.status().ok());
}

TEST(CcStreamingAeadWrappersTest, BasicNewCcDecryptingStream) {
  DummyStreamingAead dummy_saead = DummyStreamingAead("Some streaming AEAD");
  std::unique_ptr<PythonFileObjectAdapter> input =
      absl::make_unique<test::TestReadableObject>("data");

  auto result =
      NewCcDecryptingStream(&dummy_saead, "associated data", std::move(input));

  EXPECT_TRUE(result.status().ok());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
