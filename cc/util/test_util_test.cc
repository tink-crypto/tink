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
#include "tink/util/test_util.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/subtle/random.h"
#include "proto/aes_gcm.pb.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace test {
namespace {

using ::google::crypto::tink::AesGcmKey;
using ::google::crypto::tink::KeyData;
using ::testing::Eq;

TEST(AsKeyDataTest, Basic) {
  AesGcmKey key;
  key.set_key_value(crypto::tink::subtle::Random::GetRandomBytes(11));

  KeyData key_data = AsKeyData(key, KeyData::SYMMETRIC);

  EXPECT_THAT(key_data.type_url(),
              Eq("type.googleapis.com/google.crypto.tink.AesGcmKey"));
  EXPECT_THAT(key_data.key_material_type(), Eq(KeyData::SYMMETRIC));
  AesGcmKey deserialized_key;
  EXPECT_TRUE(deserialized_key.ParseFromString(key_data.value()));
  EXPECT_THAT(deserialized_key.key_value(), Eq(key.key_value()));
}

}  // namespace

}  // namespace test
}  // namespace tink
}  // namespace crypto
