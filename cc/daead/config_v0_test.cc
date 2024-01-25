// Copyright 2023 Google LLC
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
////////////////////////////////////////////////////////////////////////////////

#include "tink/daead/config_v0.h"

#include <memory>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/daead/deterministic_aead_key_templates.h"
#include "tink/daead/key_gen_config_v0.h"
#include "tink/deterministic_aead.h"
#include "tink/keyset_handle.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;

TEST(ConfigV0Test, GetPrimitive) {
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(DeterministicAeadKeyTemplates::Aes256Siv(),
                                KeyGenConfigDeterministicAeadV0());
  ASSERT_THAT(handle, IsOk());

  util::StatusOr<std::unique_ptr<DeterministicAead>> daead =
      (*handle)->GetPrimitive<DeterministicAead>(ConfigDeterministicAeadV0());
  ASSERT_THAT(daead, IsOk());

  std::string plaintext = "plaintext";
  util::StatusOr<std::string> ciphertext =
      (*daead)->EncryptDeterministically(plaintext, "ad");
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*daead)->DecryptDeterministically(*ciphertext, "ad"),
              IsOkAndHolds(plaintext));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
