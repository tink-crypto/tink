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
#include "pqcrypto/cc/subtle/hrss_boringssl.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/subtle/random.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace experimental {
namespace pqcrypto {
namespace subtle {
namespace {

using ::crypto::tink::test::IsOk;

TEST(HrssBoringSslTest, TestKeyGen) {
  auto hrss_kem_or_status = HrssKem::New();
  ASSERT_THAT(hrss_kem_or_status.status(), IsOk());
}

TEST(HrssBoringSslTest, TestEncapsDecaps) {
  // creating new HrssKem instance
  auto hrss_kem_or_status = HrssKem::New();
  EXPECT_TRUE(hrss_kem_or_status.ok()) << hrss_kem_or_status.status();
  std::unique_ptr<HrssKem> hrss_kem =
      std::move(hrss_kem_or_status.ValueOrDie());

  // creating random plaintext and performing encapsulation
  std::string random_plaintext =
      crypto::tink::subtle::Random::GetRandomBytes(HRSS_ENCAP_BYTES);
  auto kem_ct_shared_key_or_status = hrss_kem->Encapsulate(random_plaintext);
  EXPECT_TRUE(kem_ct_shared_key_or_status.ok())
      << kem_ct_shared_key_or_status.status();
  auto kem_ct_shared_key = std::move(kem_ct_shared_key_or_status.ValueOrDie());

  // performing decapsulation
  auto recovered_shared_secret_or_status =
      hrss_kem->Decapsulate(kem_ct_shared_key.kem_ciphertext);
  EXPECT_TRUE(recovered_shared_secret_or_status.ok())
      << recovered_shared_secret_or_status.status();
  auto recovered_shared_secret =
      std::move(recovered_shared_secret_or_status.ValueOrDie());

  // checking is results match
  ASSERT_EQ(kem_ct_shared_key.kem_shared_key, recovered_shared_secret);
}

}  // namespace
}  // namespace subtle
}  // namespace pqcrypto
}  // namespace experimental
}  // namespace tink
}  // namespace crypto
