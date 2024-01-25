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

#include "tink/streamingaead/internal/config_v0.h"

#include <memory>
#include <sstream>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "tink/configuration.h"
#include "tink/input_stream.h"
#include "tink/internal/configuration_impl.h"
#include "tink/internal/key_gen_configuration_impl.h"
#include "tink/internal/key_type_info_store.h"
#include "tink/internal/keyset_wrapper_store.h"
#include "tink/key_gen_configuration.h"
#include "tink/keyset_handle.h"
#include "tink/output_stream.h"
#include "tink/streaming_aead.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_key_manager.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_key_manager.h"
#include "tink/streamingaead/internal/key_gen_config_v0.h"
#include "tink/streamingaead/streaming_aead_key_templates.h"
#include "tink/subtle/test_util.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/ostream_output_stream.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::subtle::test::ReadFromStream;
using ::crypto::tink::subtle::test::WriteToStream;
using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::KeyTemplate;

TEST(StreamingAeadV0Test, PrimitiveWrappers) {
  Configuration config;
  ASSERT_THAT(AddStreamingAeadV0(config), IsOk());
  util::StatusOr<const KeysetWrapperStore*> store =
      ConfigurationImpl::GetKeysetWrapperStore(config);
  ASSERT_THAT(store, IsOk());

  EXPECT_THAT((*store)->Get<StreamingAead>(), IsOk());
}

TEST(StreamingAeadV0Test, KeyManagers) {
  Configuration config;
  ASSERT_THAT(AddStreamingAeadV0(config), IsOk());
  util::StatusOr<const KeyTypeInfoStore*> store =
      ConfigurationImpl::GetKeyTypeInfoStore(config);
  ASSERT_THAT(store, IsOk());

  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddStreamingAeadKeyGenV0(key_gen_config), IsOk());
  util::StatusOr<const KeyTypeInfoStore*> key_gen_store =
      KeyGenConfigurationImpl::GetKeyTypeInfoStore(key_gen_config);
  ASSERT_THAT(key_gen_store, IsOk());

  for (const KeyTypeInfoStore* s : {*store, *key_gen_store}) {
    EXPECT_THAT(s->Get(AesCtrHmacStreamingKeyManager().get_key_type()), IsOk());
    EXPECT_THAT(s->Get(AesGcmHkdfStreamingKeyManager().get_key_type()), IsOk());
  }
}

TEST(StreamingAeadV0Test, GetPrimitive) {
  KeyGenConfiguration key_gen_config;
  ASSERT_THAT(AddStreamingAeadKeyGenV0(key_gen_config), IsOk());
  Configuration config;
  ASSERT_THAT(AddStreamingAeadV0(config), IsOk());

  for (const KeyTemplate& temp :
       {StreamingAeadKeyTemplates::Aes128CtrHmacSha256Segment4KB(),
        StreamingAeadKeyTemplates::Aes128GcmHkdf4KB()}) {
    util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
        KeysetHandle::GenerateNew(temp, key_gen_config);
    ASSERT_THAT(handle, IsOk());

    util::StatusOr<std::unique_ptr<StreamingAead>> saead =
        (*handle)->GetPrimitive<StreamingAead>(config);
    ASSERT_THAT(saead, IsOk());

    std::string plaintext = "plaintext";
    std::string ad = "ad";

    auto ciphertext = absl::make_unique<std::stringstream>();
    std::stringbuf* const ciphertext_buf = ciphertext->rdbuf();

    auto ciphertext_out_stream =
        absl::make_unique<util::OstreamOutputStream>(std::move(ciphertext));
    util::StatusOr<std::unique_ptr<OutputStream>> encrypt =
        (*saead)->NewEncryptingStream(std::move(ciphertext_out_stream), ad);
    ASSERT_THAT(encrypt, IsOk());
    ASSERT_THAT(WriteToStream((*encrypt).get(), plaintext), IsOk());

    auto ciphertext_in =
        absl::make_unique<std::stringstream>(ciphertext_buf->str());
    auto ciphertext_in_stream =
        absl::make_unique<util::IstreamInputStream>(std::move(ciphertext_in));
    util::StatusOr<std::unique_ptr<InputStream>> decrypt =
        (*saead)->NewDecryptingStream(std::move(ciphertext_in_stream), ad);
    ASSERT_THAT(decrypt, IsOk());
    std::string got;
    ASSERT_THAT(ReadFromStream((*decrypt).get(), &got), IsOk());
    EXPECT_EQ(got, plaintext);
  }
}

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
