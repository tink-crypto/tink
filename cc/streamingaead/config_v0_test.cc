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

#include "tink/streamingaead/config_v0.h"

#include <memory>
#include <sstream>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "tink/input_stream.h"
#include "tink/keyset_handle.h"
#include "tink/output_stream.h"
#include "tink/streaming_aead.h"
#include "tink/streamingaead/key_gen_config_v0.h"
#include "tink/streamingaead/streaming_aead_key_templates.h"
#include "tink/subtle/test_util.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/ostream_output_stream.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::subtle::test::ReadFromStream;
using ::crypto::tink::subtle::test::WriteToStream;
using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::KeyTemplate;
using ::testing::TestWithParam;
using ::testing::Values;

using ConfigV0Test = TestWithParam<KeyTemplate>;

INSTANTIATE_TEST_SUITE_P(
    ConfigV0TestSuite, ConfigV0Test,
    Values(StreamingAeadKeyTemplates::Aes128CtrHmacSha256Segment4KB(),
           StreamingAeadKeyTemplates::Aes128GcmHkdf4KB()));

TEST_P(ConfigV0Test, GetPrimitive) {
  util::StatusOr<std::unique_ptr<KeysetHandle>> handle =
      KeysetHandle::GenerateNew(GetParam(), KeyGenConfigStreamingAeadV0());
  ASSERT_THAT(handle, IsOk());

  util::StatusOr<std::unique_ptr<StreamingAead>> saead =
      (*handle)->GetPrimitive<StreamingAead>(ConfigStreamingAeadV0());
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

}  // namespace
}  // namespace tink
}  // namespace crypto
