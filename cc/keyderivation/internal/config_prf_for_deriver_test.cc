// Copyright 2024 Google LLC
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

#include "tink/keyderivation/internal/config_prf_for_deriver.h"

#include <memory>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/prf/hkdf_prf_key_manager.h"
#include "tink/subtle/prf/streaming_prf.h"
#include "tink/util/input_stream_util.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::HkdfPrfKey;
using ::google::crypto::tink::KeyData;
using ::google::crypto::tink::SHA256;

TEST(ConfigPrfForDeriverTest, KeyManager) {
  util::StatusOr<const KeyTypeInfoStore*> store =
      ConfigurationImpl::GetKeyTypeInfoStore(ConfigPrfForDeriver());
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get(HkdfPrfKeyManager().get_key_type()), IsOk());
}

TEST(ConfigPrfForDeriverTest, GetUnwrappedPrimitive) {
  util::StatusOr<const KeyTypeInfoStore*> store =
      ConfigurationImpl::GetKeyTypeInfoStore(ConfigPrfForDeriver());
  ASSERT_THAT(store, IsOk());
  util::StatusOr<const KeyTypeInfoStore::Info*> info =
      (*store)->Get(HkdfPrfKeyManager().get_key_type());
  ASSERT_THAT(info, IsOk());

  HkdfPrfKey prf_key;
  prf_key.set_version(0);
  prf_key.set_key_value("01234567890123456789012345678901");
  prf_key.mutable_params()->set_hash(SHA256);

  util::StatusOr<std::unique_ptr<StreamingPrf>> prf =
      (*info)->GetPrimitive<StreamingPrf>(
          test::AsKeyData(prf_key, KeyData::SYMMETRIC));
  ASSERT_THAT(prf, IsOk());
  EXPECT_THAT(ReadBytesFromStream(32, (*prf)->ComputePrf("input").get()),
              IsOk());
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
