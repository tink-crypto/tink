// Copyright 2019 Google Inc.
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

#include <sstream>
#include <string>

#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "tink/output_stream.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/random.h"
#include "tink/subtle/test_util.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/ostream_output_stream.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "gtest/gtest.h"


namespace crypto {
namespace tink {
namespace subtle {
namespace {

TEST(AesGcmHkdfStreamingTest, testBasic) {
  for (HashType hkdf_hash : {SHA1, SHA256, SHA512}) {
    for (int ikm_size : {16, 32}) {
      for (int derived_key_size = 16;
           derived_key_size <= ikm_size;
           derived_key_size += 16) {
        for (int ct_segment_size : {80, 128, 200}) {
          for (int first_segment_offset : {0, 10, 16}) {
            SCOPED_TRACE(absl::StrCat(
                "hkdf_hash = ", EnumToString(hkdf_hash),
                ", ikm_size = ", ikm_size,
                ", derived_key_size = ", derived_key_size,
                ", ciphertext_segment_size = ", ct_segment_size,
                ", first_segment_offset = ", first_segment_offset));
            // Create AesGcmHkdfStreaming.
            std::string ikm = Random::GetRandomBytes(ikm_size);
            auto result = AesGcmHkdfStreaming::New(
                ikm, hkdf_hash, derived_key_size,
                ct_segment_size, first_segment_offset);
            EXPECT_TRUE(result.ok()) << result.status();
            auto streaming_aead = std::move(result.ValueOrDie());

            // Try to get an encrypting stream to a "null" ct_destination.
            std::string associated_data = "some associated data";
            auto failed_result = streaming_aead->NewEncryptingStream(
                nullptr, associated_data);
            EXPECT_FALSE(failed_result.ok());
            EXPECT_EQ(util::error::INVALID_ARGUMENT,
                      failed_result.status().error_code());
            EXPECT_PRED_FORMAT2(testing::IsSubstring, "non-null",
                                failed_result.status().error_message());

            for (int pt_size : {0, 16, 100, 1000, 10000}) {
              SCOPED_TRACE(absl::StrCat(" pt_size = ", pt_size));

              // Prepare ciphertext destination stream.
              auto ct_stream = absl::make_unique<std::stringstream>();
              // A reference to the ciphertext buffer, for later validation.
              auto ct_buf = ct_stream->rdbuf();
              std::unique_ptr<OutputStream> ct_destination(
                  absl::make_unique<util::OstreamOutputStream>(
                      std::move(ct_stream)));

              // Use AesGcmHkdfStreaming to encrypt some data.
              auto enc_stream_result = streaming_aead->NewEncryptingStream(
                  std::move(ct_destination), associated_data);
              EXPECT_TRUE(enc_stream_result.ok()) << enc_stream_result.status();
              auto enc_stream = std::move(enc_stream_result.ValueOrDie());
              std::string pt = Random::GetRandomBytes(pt_size);
              auto status = test::WriteToStream(enc_stream.get(), pt);
              EXPECT_TRUE(status.ok()) << status;
              EXPECT_EQ(pt_size, enc_stream->Position());
              std::string ct = ct_buf->str();
              EXPECT_NE(ct, pt);

              // Use AesGcmHkdfStreaming to decrypt the resulting ciphertext.
              auto ct_bytes = absl::make_unique<std::stringstream>(std::string(ct));
              std::unique_ptr<InputStream> ct_source(
                  absl::make_unique<util::IstreamInputStream>(
                      std::move(ct_bytes)));
              auto dec_stream_result = streaming_aead->NewDecryptingStream(
                  std::move(ct_source), associated_data);
              EXPECT_TRUE(dec_stream_result.ok()) << dec_stream_result.status();
              auto dec_stream = std::move(dec_stream_result.ValueOrDie());
              std::string decrypted;
              status = test::ReadFromStream(dec_stream.get(), &decrypted);
              EXPECT_TRUE(status.ok()) << status;
              EXPECT_EQ(pt, decrypted);
            }
          }
        }
      }
    }
  }
}

TEST(AesGcmHkdfStreamingTest, testIkmSmallerThanDerivedKey) {
  int ikm_size = 16;
  int derived_key_size = 17;
  int ct_segment_size = 100;
  int first_segment_offset = 10;
  HashType hkdf_hash = SHA256;
  std::string ikm = Random::GetRandomBytes(ikm_size);

  auto result = AesGcmHkdfStreaming::New(
      ikm, hkdf_hash, derived_key_size, ct_segment_size, first_segment_offset);
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "ikm too small",
                      result.status().error_message());
}

TEST(AesGcmHkdfStreamingTest, testIkmSize) {
  for (int ikm_size : {5, 10, 15}) {
    int derived_key_size = ikm_size;
    int ct_segment_size = 100;
    int first_segment_offset = 0;
    HashType hkdf_hash = SHA256;
    std::string ikm = Random::GetRandomBytes(ikm_size);

    auto result = AesGcmHkdfStreaming::New(
        ikm, hkdf_hash, derived_key_size,
        ct_segment_size, first_segment_offset);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "ikm too small",
                        result.status().error_message());
  }
}

TEST(AesGcmHkdfStreamingTest, testWrongHkdfHash) {
  int ikm_size = 16;
  int derived_key_size = 16;
  int ct_segment_size = 100;
  int first_segment_offset = 10;
  HashType hkdf_hash = SHA384;
  std::string ikm = Random::GetRandomBytes(ikm_size);

  auto result = AesGcmHkdfStreaming::New(ikm, hkdf_hash, derived_key_size,
                                         ct_segment_size, first_segment_offset);
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "unsupported hkdf_hash",
                      result.status().error_message());
}

TEST(AesGcmHkdfStreamingTest, testWrongDerivedKeySize) {
  int ikm_size = 20;
  int derived_key_size = 20;
  int ct_segment_size = 100;
  int first_segment_offset = 10;
  HashType hkdf_hash = SHA256;
  std::string ikm = Random::GetRandomBytes(ikm_size);

  auto result = AesGcmHkdfStreaming::New(
      ikm, hkdf_hash, derived_key_size, ct_segment_size, first_segment_offset);
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "must be 16 or 32",
                      result.status().error_message());
}

TEST(AesGcmHkdfStreamingTest, testWrongFirstSegmentOffset) {
  int ikm_size = 32;
  int derived_key_size = 32;
  int ct_segment_size = 100;
  int first_segment_offset = -5;
  HashType hkdf_hash = SHA256;
  std::string ikm = Random::GetRandomBytes(ikm_size);

  auto result = AesGcmHkdfStreaming::New(
      ikm, hkdf_hash, derived_key_size, ct_segment_size, first_segment_offset);
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "must be non-negative",
                      result.status().error_message());
}

TEST(AesGcmHkdfStreamingTest, testWrongCiphertextSegmentSize) {
  int ikm_size = 32;
  int derived_key_size = 32;
  int ct_segment_size = 64;
  int first_segment_offset = 40;
  HashType hkdf_hash = SHA256;
  std::string ikm = Random::GetRandomBytes(ikm_size);

  auto result = AesGcmHkdfStreaming::New(
      ikm, hkdf_hash, derived_key_size, ct_segment_size, first_segment_offset);
  EXPECT_FALSE(result.ok());
  EXPECT_EQ(util::error::INVALID_ARGUMENT, result.status().error_code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "ciphertext_segment_size too small",
                      result.status().error_message());
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
