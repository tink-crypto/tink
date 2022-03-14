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

#include "tink/subtle/aes_ctr_hmac_streaming.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/config/tink_fips.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/random.h"
#include "tink/subtle/stream_segment_decrypter.h"
#include "tink/subtle/stream_segment_encrypter.h"
#include "tink/subtle/streaming_aead_test_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::HasSubstr;

namespace crypto {
namespace tink {
namespace subtle {
namespace {

AesCtrHmacStreaming::Params ValidParams() {
  AesCtrHmacStreaming::Params params;
  params.ikm = Random::GetRandomKeyBytes(32);
  params.hkdf_algo = SHA256;
  params.key_size = 32;
  params.ciphertext_segment_size = 256;
  params.ciphertext_offset = 0;
  params.tag_algo = SHA256;
  params.tag_size = 16;
  return params;
}

TEST(AesCtrHmacStreamSegmentEncrypterTest, Basic) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  for (int ikm_size : {16, 32}) {
    for (HashType hkdf_algo : {SHA1, SHA256, SHA512}) {
      for (int key_size : {16, 32}) {
        if (ikm_size < key_size) continue;
        for (int ciphertext_segment_size : {80, 128, 200}) {
          for (int ciphertext_offset : {0, 5, 10}) {
            for (HashType tag_algo : {SHA1, SHA256, SHA512}) {
              for (int tag_size : {10, 16, 20}) {
                SCOPED_TRACE(absl::StrCat(
                    "ikm_size = ", ikm_size, ", hkdf_algo = ",
                    EnumToString(hkdf_algo), ", key_size = ", key_size,
                    ", ciphertext_segment_size = ", ciphertext_segment_size,
                    ", ciphertext_offset = ", ciphertext_offset,
                    ", tag_algo = ", EnumToString(tag_algo),
                    ", tag_size = ", tag_size));

                // Construct the parameters.
                AesCtrHmacStreaming::Params params;
                params.ikm = Random::GetRandomKeyBytes(ikm_size);
                params.hkdf_algo = hkdf_algo;
                params.key_size = key_size;
                params.ciphertext_segment_size = ciphertext_segment_size;
                params.ciphertext_offset = ciphertext_offset;
                params.tag_algo = tag_algo;
                params.tag_size = tag_size;
                std::string associated_data = "associated data";

                // Get a segment encrypter.
                auto enc_result = AesCtrHmacStreamSegmentEncrypter::New(
                    params, associated_data);
                ASSERT_THAT(enc_result.status(), IsOk());
                auto enc = std::move(enc_result.ValueOrDie());
                EXPECT_EQ(0, enc->get_segment_number());
                int header_size = 1 + key_size + /* nonce_prefix_size = */ 7;
                EXPECT_EQ(header_size, enc->get_header().size());
                EXPECT_EQ(header_size, enc->get_header()[0]);
                EXPECT_EQ(ciphertext_segment_size,
                          enc->get_ciphertext_segment_size());
                EXPECT_EQ(ciphertext_segment_size - tag_size,
                          enc->get_plaintext_segment_size());
                EXPECT_EQ(ciphertext_offset, enc->get_ciphertext_offset());

                int segment_number = 0;
                for (int pt_size :
                     {0, 1, 10, enc->get_plaintext_segment_size()}) {
                  for (bool is_last_segment : {false, true}) {
                    SCOPED_TRACE(
                        absl::StrCat("plaintext_size = ", pt_size,
                                     ", is_last_segment = ", is_last_segment));
                    std::vector<uint8_t> pt(pt_size, 'p');
                    std::vector<uint8_t> ct;
                    EXPECT_THAT(enc->EncryptSegment(pt, is_last_segment, &ct),
                                IsOk());
                    EXPECT_EQ(ct.size(), pt.size() + tag_size);
                    segment_number++;
                    EXPECT_EQ(segment_number, enc->get_segment_number());
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}

TEST(AesCtrHmacStreamSegmentEncrypterTest, EncryptLongPlaintext) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  AesCtrHmacStreaming::Params params = ValidParams();
  std::string associated_data = "associated data";

  auto enc_result =
      AesCtrHmacStreamSegmentEncrypter::New(params, associated_data);
  ASSERT_THAT(enc_result.status(), IsOk());
  auto enc = std::move(enc_result.ValueOrDie());

  std::vector<uint8_t> pt(enc->get_plaintext_segment_size() + 1, 'p');
  std::vector<uint8_t> ct;
  ASSERT_THAT(enc->EncryptSegment(pt, true, &ct),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("plaintext too long")));
}

TEST(AesCtrHmacStreamSegmentEncrypterTest, EncryptNullCtBuffer) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  AesCtrHmacStreaming::Params params = ValidParams();
  std::string associated_data = "associated data";

  auto enc_result =
      AesCtrHmacStreamSegmentEncrypter::New(params, associated_data);
  ASSERT_THAT(enc_result.status(), IsOk());
  auto enc = std::move(enc_result.ValueOrDie());

  std::vector<uint8_t> pt(enc->get_plaintext_segment_size(), 'p');
  ASSERT_THAT(enc->EncryptSegment(pt, true, nullptr),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("must be non-null")));
}

TEST(AesCtrHmacStreamSegmentDecrypterTest, Basic) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  for (int ikm_size : {16, 32}) {
    for (HashType hkdf_algo : {SHA1, SHA256, SHA512}) {
      for (int key_size : {16, 32}) {
        if (ikm_size < key_size) continue;
        for (int ciphertext_segment_size : {80, 128, 200}) {
          for (int ciphertext_offset : {0, 5, 10}) {
            for (HashType tag_algo : {SHA1, SHA256, SHA512}) {
              for (int tag_size : {10, 16, 20}) {
                SCOPED_TRACE(absl::StrCat(
                    "ikm_size = ", ikm_size, ", hkdf_algo = ",
                    EnumToString(hkdf_algo), ", key_size = ", key_size,
                    ", ciphertext_segment_size = ", ciphertext_segment_size,
                    ", ciphertext_offset = ", ciphertext_offset,
                    ", tag_algo = ", EnumToString(tag_algo),
                    ", tag_size = ", tag_size));

                // Construct the parameters.
                AesCtrHmacStreaming::Params params;
                params.ikm = Random::GetRandomKeyBytes(ikm_size);
                params.hkdf_algo = hkdf_algo;
                params.key_size = key_size;
                params.ciphertext_segment_size = ciphertext_segment_size;
                params.ciphertext_offset = ciphertext_offset;
                params.tag_algo = tag_algo;
                params.tag_size = tag_size;
                std::string associated_data = "associated data";

                // Get a segment encrypter.
                auto enc_result = AesCtrHmacStreamSegmentEncrypter::New(
                    params, associated_data);
                ASSERT_THAT(enc_result.status(), IsOk());
                auto enc = std::move(enc_result.ValueOrDie());

                // Get and initialize a segment decrypter.
                auto dec_result = AesCtrHmacStreamSegmentDecrypter::New(
                    params, associated_data);
                ASSERT_THAT(dec_result.status(), IsOk());
                auto dec = std::move(dec_result.ValueOrDie());
                ASSERT_THAT(dec->Init(enc->get_header()), IsOk());
                int header_size = 1 + key_size + /* nonce_prefix_size = */ 7;
                EXPECT_EQ(header_size, dec->get_header_size());
                EXPECT_EQ(enc->get_header().size(), dec->get_header_size());
                EXPECT_EQ(ciphertext_segment_size,
                          dec->get_ciphertext_segment_size());
                EXPECT_EQ(ciphertext_segment_size - tag_size,
                          dec->get_plaintext_segment_size());
                EXPECT_EQ(ciphertext_offset, dec->get_ciphertext_offset());

                int segment_number = 0;
                for (int pt_size :
                     {0, 1, 10, dec->get_plaintext_segment_size()}) {
                  for (bool is_last_segment : {false, true}) {
                    SCOPED_TRACE(
                        absl::StrCat("plaintext_size = ", pt_size,
                                     ", is_last_segment = ", is_last_segment));
                    std::vector<uint8_t> pt(pt_size, 'p');
                    std::vector<uint8_t> ct;
                    std::vector<uint8_t> decrypted;
                    auto status = enc->EncryptSegment(pt, is_last_segment, &ct);
                    EXPECT_THAT(status, IsOk());
                    EXPECT_EQ(ct.size(), pt.size() + tag_size);
                    EXPECT_THAT(
                        dec->DecryptSegment(ct, segment_number, is_last_segment,
                                            &decrypted),
                        IsOk());
                    EXPECT_EQ(pt, decrypted);
                    segment_number++;
                    EXPECT_EQ(segment_number, enc->get_segment_number());
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}

TEST(AesCtrHmacStreamSegmentDecrypterTest, AlreadyInit) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  AesCtrHmacStreaming::Params params = ValidParams();
  std::string associated_data = "associated data";

  auto enc_result =
      AesCtrHmacStreamSegmentEncrypter::New(params, associated_data);
  ASSERT_THAT(enc_result.status(), IsOk());
  auto enc = std::move(enc_result.ValueOrDie());
  auto dec_result =
      AesCtrHmacStreamSegmentDecrypter::New(params, associated_data);
  ASSERT_THAT(dec_result.status(), IsOk());
  auto dec = std::move(dec_result.ValueOrDie());
  ASSERT_THAT(dec->Init(enc->get_header()), IsOk());
  ASSERT_THAT(dec->Init(enc->get_header()),
              StatusIs(absl::StatusCode::kFailedPrecondition,
                       HasSubstr("alreday initialized")));
}

TEST(AesCtrHmacStreamSegmentDecrypterTest, InitWrongHeaderSize) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  AesCtrHmacStreaming::Params params = ValidParams();
  std::string associated_data = "associated data";

  auto enc_result =
      AesCtrHmacStreamSegmentEncrypter::New(params, associated_data);
  ASSERT_THAT(enc_result.status(), IsOk());
  auto enc = std::move(enc_result.ValueOrDie());
  auto dec_result =
      AesCtrHmacStreamSegmentDecrypter::New(params, associated_data);
  ASSERT_THAT(dec_result.status(), IsOk());
  auto dec = std::move(dec_result.ValueOrDie());
  auto header = enc->get_header();
  header.resize(dec->get_header_size() - 1);
  ASSERT_THAT(dec->Init(header), StatusIs(absl::StatusCode::kInvalidArgument,
                                          HasSubstr("wrong header size")));
}

TEST(AesCtrHmacStreamSegmentDecrypterTest, InitCorruptedHeader) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  AesCtrHmacStreaming::Params params = ValidParams();
  std::string associated_data = "associated data";

  auto enc_result =
      AesCtrHmacStreamSegmentEncrypter::New(params, associated_data);
  ASSERT_THAT(enc_result.status(), IsOk());
  auto enc = std::move(enc_result.ValueOrDie());
  auto dec_result =
      AesCtrHmacStreamSegmentDecrypter::New(params, associated_data);
  ASSERT_THAT(dec_result.status(), IsOk());
  auto dec = std::move(dec_result.ValueOrDie());
  auto header = enc->get_header();
  header[0] = 0;
  ASSERT_THAT(dec->Init(header), StatusIs(absl::StatusCode::kInvalidArgument,
                                          HasSubstr("corrupted header")));
}

TEST(AesCtrHmacStreamSegmentDecrypterTest, DecryptNotInit) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  AesCtrHmacStreaming::Params params = ValidParams();
  std::string associated_data = "associated data";

  auto enc_result =
      AesCtrHmacStreamSegmentEncrypter::New(params, associated_data);
  ASSERT_THAT(enc_result.status(), IsOk());
  auto enc = std::move(enc_result.ValueOrDie());
  auto dec_result =
      AesCtrHmacStreamSegmentDecrypter::New(params, associated_data);
  ASSERT_THAT(dec_result.status(), IsOk());
  auto dec = std::move(dec_result.ValueOrDie());

  std::vector<uint8_t> ct(dec->get_ciphertext_segment_size(), 'c');
  std::vector<uint8_t> pt;
  ASSERT_THAT(dec->DecryptSegment(ct, 0, true, &pt),
              StatusIs(absl::StatusCode::kFailedPrecondition,
                       HasSubstr("not initialized")));
}

TEST(AesCtrHmacStreamSegmentDecrypterTest, DecryptLongCiphertext) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  AesCtrHmacStreaming::Params params = ValidParams();
  std::string associated_data = "associated data";

  auto enc_result =
      AesCtrHmacStreamSegmentEncrypter::New(params, associated_data);
  ASSERT_THAT(enc_result.status(), IsOk());
  auto enc = std::move(enc_result.ValueOrDie());
  auto dec_result =
      AesCtrHmacStreamSegmentDecrypter::New(params, associated_data);
  ASSERT_THAT(dec_result.status(), IsOk());
  auto dec = std::move(dec_result.ValueOrDie());
  ASSERT_THAT(dec->Init(enc->get_header()), IsOk());

  std::vector<uint8_t> ct(dec->get_ciphertext_segment_size() + 1, 'c');
  std::vector<uint8_t> pt;
  ASSERT_THAT(dec->DecryptSegment(ct, 0, true, &pt),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("ciphertext too long")));
}

TEST(AesCtrHmacStreamSegmentDecrypterTest, DecryptNullPtBuffer) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  AesCtrHmacStreaming::Params params = ValidParams();
  std::string associated_data = "associated data";

  auto enc_result =
      AesCtrHmacStreamSegmentEncrypter::New(params, associated_data);
  ASSERT_THAT(enc_result.status(), IsOk());
  auto enc = std::move(enc_result.ValueOrDie());
  auto dec_result =
      AesCtrHmacStreamSegmentDecrypter::New(params, associated_data);
  ASSERT_THAT(dec_result.status(), IsOk());
  auto dec = std::move(dec_result.ValueOrDie());
  ASSERT_THAT(dec->Init(enc->get_header()), IsOk());

  std::vector<uint8_t> ct(dec->get_ciphertext_segment_size(), 'c');
  ASSERT_THAT(dec->DecryptSegment(ct, 0, true, nullptr),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("must be non-null")));
}

TEST(AesCtrHmacStreamingTest, Basic) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  for (int ikm_size : {16, 32}) {
    for (HashType hkdf_algo : {SHA1, SHA256, SHA512}) {
      for (int key_size : {16, 32}) {
        if (ikm_size < key_size) continue;
        for (int ciphertext_segment_size : {80, 128, 200}) {
          for (int ciphertext_offset : {0, 5, 10}) {
            for (HashType tag_algo : {SHA1, SHA256, SHA512}) {
              for (int tag_size : {10, 16, 20}) {
                for (int plaintext_size : {0, 10, 100, 1000}) {
                  SCOPED_TRACE(absl::StrCat(
                      "ikm_size = ", ikm_size, ", hkdf_algo = ",
                      EnumToString(hkdf_algo), ", key_size = ", key_size,
                      ", ciphertext_segment_size = ", ciphertext_segment_size,
                      ", ciphertext_offset = ", ciphertext_offset,
                      ", tag_algo = ", EnumToString(tag_algo), ", tag_size = ",
                      tag_size, ", plaintext_size = ", plaintext_size));

                  // Create AesCtrHmacStreaming.
                  AesCtrHmacStreaming::Params params;
                  params.ikm = Random::GetRandomKeyBytes(ikm_size);
                  params.hkdf_algo = hkdf_algo;
                  params.key_size = key_size;
                  params.ciphertext_segment_size = ciphertext_segment_size;
                  params.ciphertext_offset = ciphertext_offset;
                  params.tag_algo = tag_algo;
                  params.tag_size = tag_size;
                  auto result = AesCtrHmacStreaming::New(params);
                  ASSERT_THAT(result.status(), IsOk());
                  auto streaming_aead = std::move(result.ValueOrDie());

                  std::string plaintext(plaintext_size, 'p');
                  std::string associated_data = "associated data";

                  EXPECT_THAT(
                      EncryptThenDecrypt(streaming_aead.get(),
                                         streaming_aead.get(), plaintext,
                                         associated_data, ciphertext_offset),
                      IsOk());
                }
              }
            }
          }
        }
      }
    }
  }
}

TEST(ValidateTest, ValidParams) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  AesCtrHmacStreaming::Params params = ValidParams();
  ASSERT_THAT(AesCtrHmacStreaming::New(params).status(), IsOk());
}

TEST(ValidateTest, WrongIkm) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  AesCtrHmacStreaming::Params params = ValidParams();
  params.ikm = Random::GetRandomKeyBytes(16);
  ASSERT_THAT(AesCtrHmacStreaming::New(params).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("key material too small")));
}

TEST(ValidateTest, WrongHkdfAlgo) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  AesCtrHmacStreaming::Params params = ValidParams();
  params.hkdf_algo = SHA384;
  ASSERT_THAT(AesCtrHmacStreaming::New(params).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("unsupported hkdf_algo")));
}

TEST(ValidateTest, WrongKeySize) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  AesCtrHmacStreaming::Params params = ValidParams();
  params.ikm = Random::GetRandomKeyBytes(64);
  params.key_size = 64;
  ASSERT_THAT(AesCtrHmacStreaming::New(params).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("key_size must be")));
}

TEST(ValidateTest, WrongCtSegmentSize) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  AesCtrHmacStreaming::Params params = ValidParams();
  params.ciphertext_segment_size = 10;
  ASSERT_THAT(AesCtrHmacStreaming::New(params).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("ciphertext_segment_size too small")));

  params.ciphertext_segment_size = 1 + 32 + 7 + 16;
  ASSERT_THAT(AesCtrHmacStreaming::New(params).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("ciphertext_segment_size too small")));
}

TEST(ValidateTest, WrongCtOffset) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  AesCtrHmacStreaming::Params params = ValidParams();
  params.ciphertext_offset = -10;
  ASSERT_THAT(AesCtrHmacStreaming::New(params).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("ciphertext_offset must be")));
}

TEST(ValidateTest, WrongTagSize) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  AesCtrHmacStreaming::Params params = ValidParams();
  params.tag_size = 5;
  ASSERT_THAT(AesCtrHmacStreaming::New(params).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("tag_size too small")));

  params.tag_algo = SHA1;
  params.tag_size = 21;
  ASSERT_THAT(AesCtrHmacStreaming::New(params).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("tag_size too big")));

  params.tag_algo = SHA256;
  params.tag_size = 33;
  ASSERT_THAT(AesCtrHmacStreaming::New(params).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("tag_size too big")));

  params.tag_algo = SHA512;
  params.tag_size = 65;
  ASSERT_THAT(AesCtrHmacStreaming::New(params).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("tag_size too big")));
}

TEST(ValidateTest, WrongTagAlgo) {
  if (IsFipsModeEnabled()) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  AesCtrHmacStreaming::Params params = ValidParams();
  params.tag_algo = SHA384;
  ASSERT_THAT(AesCtrHmacStreaming::New(params).status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("unsupported tag_algo")));
}

// FIPS only mode tests
TEST(AesCtrHmacStreamingTest, TestFipsOnly) {
  if (!IsFipsModeEnabled()) {
    GTEST_SKIP() << "Only supported in FIPS-only mode";
  }
  AesCtrHmacStreaming::Params params = ValidParams();

  EXPECT_THAT(AesCtrHmacStreaming::New(std::move(params)).status(),
              StatusIs(absl::StatusCode::kInternal));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
