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

#include "tink/subtle/aes_gcm_hkdf_streaming.h"

#include <memory>
#include <sstream>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "tink/config/tink_fips.h"
#include "tink/internal/test_random_access_stream.h"
#include "tink/output_stream.h"
#include "tink/random_access_stream.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/random.h"
#include "tink/subtle/streaming_aead_test_util.h"
#include "tink/subtle/test_util.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/ostream_output_stream.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;

TEST(AesGcmHkdfStreamingTest, testBasic) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  for (HashType hkdf_hash : {SHA1, SHA256, SHA512}) {
    for (int ikm_size : {16, 32}) {
      for (int derived_key_size = 16;
           derived_key_size <= ikm_size;
           derived_key_size += 16) {
        for (int ct_segment_size : {80, 128, 200}) {
          for (int ciphertext_offset : {0, 10, 16}) {
            SCOPED_TRACE(absl::StrCat(
                "hkdf_hash = ", EnumToString(hkdf_hash),
                ", ikm_size = ", ikm_size,
                ", derived_key_size = ", derived_key_size,
                ", ciphertext_segment_size = ", ct_segment_size,
                ", ciphertext_offset = ", ciphertext_offset));
            // Create AesGcmHkdfStreaming.
            AesGcmHkdfStreaming::Params params;
            params.ikm = Random::GetRandomKeyBytes(ikm_size);
            params.hkdf_hash = hkdf_hash;
            params.derived_key_size = derived_key_size;
            params.ciphertext_segment_size = ct_segment_size;
            params.ciphertext_offset = ciphertext_offset;
            auto result = AesGcmHkdfStreaming::New(std::move(params));
            EXPECT_TRUE(result.ok()) << result.status();
            auto streaming_aead = std::move(result.value());

            // Try to get an encrypting stream to a "null" ct_destination.
            std::string associated_data = "some associated data";
            auto failed_result = streaming_aead->NewEncryptingStream(
                nullptr, associated_data);
            EXPECT_FALSE(failed_result.ok());
            EXPECT_EQ(absl::StatusCode::kInvalidArgument,
                      failed_result.status().code());
            EXPECT_PRED_FORMAT2(testing::IsSubstring, "non-null",
                                std::string(failed_result.status().message()));

            for (int pt_size : {0, 16, 100, 1000, 10000}) {
              SCOPED_TRACE(absl::StrCat(" pt_size = ", pt_size));
              std::string pt = Random::GetRandomBytes(pt_size);
              EXPECT_THAT(
                  EncryptThenDecrypt(streaming_aead.get(), streaming_aead.get(),
                                     pt, associated_data, ciphertext_offset),
                  IsOk());
            }
          }
        }
      }
    }
  }
}

TEST(AesGcmHkdfStreamingTest, testIkmSmallerThanDerivedKey) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  AesGcmHkdfStreaming::Params params;
  int ikm_size = 16;
  params.ikm = Random::GetRandomKeyBytes(ikm_size);
  params.derived_key_size = 17;
  params.ciphertext_segment_size = 100;
  params.ciphertext_offset = 10;
  params.hkdf_hash = SHA256;
  auto result = AesGcmHkdfStreaming::New(std::move(params));
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "ikm too small",
                      std::string(result.status().message()));
}

TEST(AesGcmHkdfStreamingTest, testIkmSize) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  for (int ikm_size : {5, 10, 15}) {
    AesGcmHkdfStreaming::Params params;
    params.ikm = Random::GetRandomKeyBytes(ikm_size);
    params.derived_key_size = 17;
    params.ciphertext_segment_size = 100;
    params.ciphertext_offset = 0;
    params.hkdf_hash = SHA256;

    auto result = AesGcmHkdfStreaming::New(std::move(params));
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "ikm too small",
                        std::string(result.status().message()));
  }
}

TEST(AesGcmHkdfStreamingTest, testWrongHkdfHash) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  AesGcmHkdfStreaming::Params params;
  int ikm_size = 16;
  params.ikm = Random::GetRandomKeyBytes(ikm_size);
  params.derived_key_size = 16;
  params.ciphertext_segment_size = 100;
  params.ciphertext_offset = 10;
  params.hkdf_hash = SHA384;

  auto result = AesGcmHkdfStreaming::New(std::move(params));
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "unsupported hkdf_hash",
                      std::string(result.status().message()));
}

TEST(AesGcmHkdfStreamingTest, testWrongDerivedKeySize) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  AesGcmHkdfStreaming::Params params;
  int ikm_size = 20;
  params.ikm = Random::GetRandomKeyBytes(ikm_size);
  params.derived_key_size = 20;
  params.ciphertext_segment_size = 100;
  params.ciphertext_offset = 10;
  params.hkdf_hash = SHA256;

  auto result = AesGcmHkdfStreaming::New(std::move(params));
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "must be 16 or 32",
                      std::string(result.status().message()));
}

TEST(AesGcmHkdfStreamingTest, testWrongCiphertextOffset) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  AesGcmHkdfStreaming::Params params;
  int ikm_size = 32;
  params.ikm = Random::GetRandomKeyBytes(ikm_size);
  params.derived_key_size = 32;
  params.ciphertext_segment_size = 100;
  params.ciphertext_offset = -5;
  params.hkdf_hash = SHA256;

  auto result = AesGcmHkdfStreaming::New(std::move(params));
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "must be non-negative",
                      std::string(result.status().message()));
}

TEST(AesGcmHkdfStreamingTest, testWrongCiphertextSegmentSize) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  AesGcmHkdfStreaming::Params params;
  int ikm_size = 32;
  params.ikm = Random::GetRandomKeyBytes(ikm_size);
  params.derived_key_size = 32;
  params.ciphertext_segment_size = 64;
  params.ciphertext_offset = 40;
  params.hkdf_hash = SHA256;

  auto result = AesGcmHkdfStreaming::New(std::move(params));
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "ciphertext_segment_size too small",
                      std::string(result.status().message()));
}

TEST(AesGcmHkdfStreamingTest, SizeIsUnauthenticated) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  AesGcmHkdfStreaming::Params params;
  params.ikm = Random::GetRandomKeyBytes(16);
  params.hkdf_hash = SHA1;
  params.derived_key_size = 16;
  params.ciphertext_segment_size = 100;
  params.ciphertext_offset = 0;
  util::StatusOr<std::unique_ptr<AesGcmHkdfStreaming>> streaming_aead =
      AesGcmHkdfStreaming::New(std::move(params));
  ASSERT_THAT(streaming_aead.status(), IsOk());

  std::string associated_data = "some associated data";
  // The header is 24 = 0x18 bytes for this key and Tink verifies that the
  // ciphertext starts with 0x18 in the first byte.
  std::string wrong_ciphertext =
      absl::StrCat(absl::HexStringToBytes("18"),
                   "some arbitrary text which does not matter at all but needs "
                   "to be at least of length 24 bytes");
  absl::StatusOr<std::unique_ptr<RandomAccessStream>> plaintext_stream =
      (*streaming_aead)
          ->NewDecryptingRandomAccessStream(
              absl::make_unique<internal::TestRandomAccessStream>(
                  wrong_ciphertext),
              associated_data);
  ASSERT_THAT(plaintext_stream.status(), IsOk());
  // 53 is the length of "wrong_ciphertext" minus the overhead (header + tag).
  EXPECT_THAT((*plaintext_stream)->size(), IsOkAndHolds(Eq(53)));
}

// FIPS only mode tests
TEST(AesGcmHkdfStreamingTest, TestFipsOnly) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }
  AesGcmHkdfStreaming::Params params;
  int ikm_size = 32;
  params.ikm = Random::GetRandomKeyBytes(ikm_size);
  params.derived_key_size = 32;
  params.ciphertext_segment_size = 64;
  params.ciphertext_offset = 40;
  params.hkdf_hash = SHA256;

  EXPECT_THAT(AesGcmHkdfStreaming::New(std::move(params)).status(),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
