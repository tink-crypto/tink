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

#include "tink/config/tink_config.h"

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "tink/aead.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/config.h"
#include "tink/deterministic_aead.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/mac.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "tink/registry.h"
#include "tink/streaming_aead.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;

TEST(TinkConfigTest, RegisterWorks) {
  EXPECT_THAT(Registry::get_key_manager<Aead>(AesGcmKeyManager().get_key_type())
                  .status(),
              StatusIs(absl::StatusCode::kNotFound));
  EXPECT_THAT(TinkConfig::Register(), IsOk());
  EXPECT_THAT(Registry::get_key_manager<Aead>(AesGcmKeyManager().get_key_type())
                  .status(),
              IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
