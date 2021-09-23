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

#include "tink/subtle/aes_gcm_hkdf_stream_segment_decrypter.h"

#include <string>
#include <vector>

#include "absl/strings/str_cat.h"
#include "tink/subtle/aes_gcm_hkdf_stream_segment_encrypter.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/hkdf.h"
#include "tink/subtle/random.h"
#include "tink/subtle/stream_segment_encrypter.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"
#include "gtest/gtest.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

util::StatusOr<std::unique_ptr<StreamSegmentEncrypter>> GetEncrypter(
    const util::SecretData& ikm, HashType hkdf_hash, int derived_key_size,
    int ciphertext_offset, int ciphertext_segment_size,
    absl::string_view associated_data) {
  AesGcmHkdfStreamSegmentEncrypter::Params params;
  params.salt = Random::GetRandomBytes(derived_key_size);
  auto hkdf_result = Hkdf::ComputeHkdf(
      hkdf_hash, ikm, params.salt, associated_data,
      derived_key_size);
  if (!hkdf_result.ok()) return hkdf_result.status();
  params.key = hkdf_result.ValueOrDie();
  params.ciphertext_offset = ciphertext_offset;
  params.ciphertext_segment_size = ciphertext_segment_size;
  return AesGcmHkdfStreamSegmentEncrypter::New(params);
}

TEST(AesGcmHkdfStreamSegmentDecrypterTest, testBasic) {
  for (int ikm_size : {16, 32}) {
    for (HashType hkdf_hash : {SHA1, SHA256, SHA512}) {
      for (int derived_key_size = 16;
           derived_key_size <= ikm_size;
           derived_key_size += 16) {
        for (int ciphertext_offset : {0, 5, 10}) {
          for (int ct_segment_size : {80, 128, 200}) {
            for (std::string associated_data : {"associated data", "42", ""}) {
              SCOPED_TRACE(absl::StrCat(
                  "hkdf_hash = ", EnumToString(hkdf_hash),
                  ", ikm_size = ", ikm_size,
                  ", associated_data = '", associated_data, "'",
                  ", derived_key_size = ", derived_key_size,
                  ", ciphertext_offset = ", ciphertext_offset,
                  ", ciphertext_segment_size = ", ct_segment_size));

              // Construct a decrypter.
              AesGcmHkdfStreamSegmentDecrypter::Params params;
              params.ikm = Random::GetRandomKeyBytes(ikm_size);
              params.hkdf_hash = hkdf_hash;
              params.derived_key_size = derived_key_size;
              params.ciphertext_offset = ciphertext_offset;
              params.ciphertext_segment_size = ct_segment_size;
              params.associated_data = associated_data;
              auto result = AesGcmHkdfStreamSegmentDecrypter::New(params);
              EXPECT_TRUE(result.ok()) << result.status();
              auto dec = std::move(result.ValueOrDie());

              // Try to use the decrypter.
              std::vector<uint8_t> pt;
              auto status = dec->DecryptSegment(pt, 42, false, nullptr);
              EXPECT_FALSE(status.ok());
              EXPECT_EQ(absl::StatusCode::kFailedPrecondition, status.code());
              EXPECT_PRED_FORMAT2(testing::IsSubstring, "not initialized",
                                  status.error_message());

              // Get an encrypter and initialize the decrypter.
              auto enc = std::move(
                  GetEncrypter(params.ikm, hkdf_hash, derived_key_size,
                               ciphertext_offset, ct_segment_size,
                               associated_data).ValueOrDie());
              status = dec->Init(enc->get_header());
              EXPECT_TRUE(status.ok()) << status;

              // Use the constructed decrypter.
              int header_size =
                  derived_key_size + /* nonce_prefix_size = */ 7 + 1;
              EXPECT_EQ(header_size, dec->get_header_size());
              EXPECT_EQ(enc->get_header().size(), dec->get_header_size());
              EXPECT_EQ(ct_segment_size, dec->get_ciphertext_segment_size());
              EXPECT_EQ(ct_segment_size - /* tag_size = */ 16,
                        dec->get_plaintext_segment_size());
              EXPECT_EQ(ciphertext_offset, dec->get_ciphertext_offset());
              int segment_number = 0;
              for (int pt_size : {1, 10, dec->get_plaintext_segment_size()}) {
                for (bool is_last_segment : {false, true}) {
                  SCOPED_TRACE(absl::StrCat(
                      "plaintext_size = ", pt_size,
                      ", is_last_segment = ", is_last_segment));
                  std::vector<uint8_t> pt(pt_size, 'p');
                  std::vector<uint8_t> ct;
                  std::vector<uint8_t> decrypted;
                  auto status = enc->EncryptSegment(pt, is_last_segment, &ct);
                  EXPECT_TRUE(status.ok()) << status;
                  status = dec->DecryptSegment(ct, segment_number,
                                               is_last_segment, &decrypted);
                  EXPECT_TRUE(status.ok()) << status;
                  EXPECT_EQ(pt, decrypted);
                  segment_number++;
                  EXPECT_EQ(segment_number, enc->get_segment_number());
                }
              }

              // Try decryption with wrong params.
              std::vector<uint8_t> ct(
                  dec->get_ciphertext_segment_size() + 1, 'c');
              status = dec->DecryptSegment(ct, 42, true, nullptr);
              EXPECT_FALSE(status.ok());
              EXPECT_PRED_FORMAT2(testing::IsSubstring, "ciphertext too long",
                                  status.error_message());
              ct.resize(dec->get_plaintext_segment_size());
              status = dec->DecryptSegment(ct, 42, true, nullptr);
              EXPECT_FALSE(status.ok());
              EXPECT_PRED_FORMAT2(testing::IsSubstring, "must be non-null",
                                  status.error_message());
            }
          }
        }
      }
    }
  }
}


TEST(AesGcmHkdfStreamSegmentDecrypterTest, testWrongDerivedKeySize) {
  for (int derived_key_size : {12, 24, 64}) {
    for (HashType hkdf_hash : {SHA1, SHA256, SHA512}) {
      for (int ct_segment_size : {128, 200}) {
        SCOPED_TRACE(absl::StrCat(
            "derived_key_size = ", derived_key_size,
            ", hkdf_hash = ", EnumToString(hkdf_hash),
            ", ciphertext_segment_size = ", ct_segment_size));
        AesGcmHkdfStreamSegmentDecrypter::Params params;
        params.ikm = Random::GetRandomKeyBytes(derived_key_size);
        params.hkdf_hash = hkdf_hash;
        params.derived_key_size = derived_key_size;
        params.ciphertext_offset = 0;
        params.ciphertext_segment_size = ct_segment_size;
        params.associated_data = "associated data";
        auto result = AesGcmHkdfStreamSegmentDecrypter::New(params);
        EXPECT_FALSE(result.ok());
        EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
        EXPECT_PRED_FORMAT2(testing::IsSubstring, "must be 16 or 32",
                            result.status().error_message());
      }
    }
  }
}

TEST(AesGcmHkdfStreamSegmentDecrypterTest, testWrongIkmSize) {
  for (int derived_key_size : {16, 32}) {
    for (HashType hkdf_hash : {SHA1, SHA256, SHA512}) {
      for (int ikm_size_delta : {-8, -4, -2, -1}) {
        SCOPED_TRACE(absl::StrCat(
            "derived_key_size = ", derived_key_size,
            ", hkdf_hash = ", EnumToString(hkdf_hash),
            ", ikm_size_delta = ", ikm_size_delta));
        AesGcmHkdfStreamSegmentDecrypter::Params params;
        params.ikm =
            Random::GetRandomKeyBytes(derived_key_size + ikm_size_delta);
        params.hkdf_hash = hkdf_hash;
        params.derived_key_size = derived_key_size;
        params.ciphertext_offset = 0;
        params.ciphertext_segment_size = 128;
        params.associated_data = "associated data";
        auto result = AesGcmHkdfStreamSegmentDecrypter::New(params);
        EXPECT_FALSE(result.ok());
        EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
        EXPECT_PRED_FORMAT2(testing::IsSubstring, "ikm too small",
                            result.status().error_message());
      }
    }
  }
}

TEST(AesGcmHkdfStreamSegmentDecrypterTest, testWrongCiphertextOffset) {
  for (int derived_key_size : {16, 32}) {
    for (HashType hkdf_hash : {SHA1, SHA256, SHA512}) {
      for (int ciphertext_offset : {-16, -10, -3, -1}) {
        SCOPED_TRACE(absl::StrCat(
            "derived_key_size = ", derived_key_size,
            ", hkdf_hash = ", EnumToString(hkdf_hash),
            ", ciphertext_offset = ", ciphertext_offset));
        AesGcmHkdfStreamSegmentDecrypter::Params params;
        params.ikm = Random::GetRandomKeyBytes(derived_key_size);
        params.hkdf_hash = hkdf_hash;
        params.derived_key_size = derived_key_size;
        params.ciphertext_offset = ciphertext_offset;
        params.ciphertext_segment_size = 128;
        params.associated_data = "associated data";
        auto result = AesGcmHkdfStreamSegmentDecrypter::New(params);
        EXPECT_FALSE(result.ok());
        EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
        EXPECT_PRED_FORMAT2(testing::IsSubstring, "must be non-negative",
                            result.status().error_message());
      }
    }
  }
}

TEST(AesGcmHkdfStreamSegmentDecrypterTest, testWrongCiphertextSegmentSize) {
  for (int derived_key_size : {16, 32}) {
    for (HashType hkdf_hash : {SHA1, SHA256, SHA512}) {
      for (int ciphertext_offset : {0, 1, 5, 10}) {
        int min_ct_segment_size = derived_key_size + ciphertext_offset +
                                  8 +   // nonce_prefix_size + 1
                                  16 +   // tag_size
                                  1;

        for (int ct_segment_size : {min_ct_segment_size - 5,
                min_ct_segment_size - 1, min_ct_segment_size,
                min_ct_segment_size + 1, min_ct_segment_size + 10}) {
          SCOPED_TRACE(absl::StrCat(
              "derived_key_size = ", derived_key_size,
              ", ciphertext_offset = ", ciphertext_offset,
              ", ciphertext_segment_size = ", ct_segment_size));
          AesGcmHkdfStreamSegmentDecrypter::Params params;
          params.ikm = Random::GetRandomKeyBytes(derived_key_size);
          params.hkdf_hash = hkdf_hash;
          params.derived_key_size = derived_key_size;
          params.ciphertext_offset = ciphertext_offset;
          params.ciphertext_segment_size = ct_segment_size;
          auto result = AesGcmHkdfStreamSegmentDecrypter::New(params);
          if (ct_segment_size < min_ct_segment_size) {
            EXPECT_FALSE(result.ok());
            EXPECT_EQ(absl::StatusCode::kInvalidArgument,
                      result.status().code());
            EXPECT_PRED_FORMAT2(testing::IsSubstring, "too small",
                                result.status().error_message());
          } else {
            EXPECT_TRUE(result.ok()) << result.status();
          }
        }
      }
    }
  }
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
