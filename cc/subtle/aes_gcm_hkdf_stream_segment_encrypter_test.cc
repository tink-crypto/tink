// Copyright 2017 Google Inc.
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

#include "tink/subtle/aes_gcm_hkdf_stream_segment_encrypter.h"

#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/subtle/random.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_util.h"


namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::testing::HasSubstr;

TEST(AesGcmHkdfStreamSegmentEncrypterTest, testBasic) {
  for (int key_size : {16, 32}) {
    for (int ciphertext_offset : {0, 5, 10}) {
      for (int ct_segment_size : {80, 128, 200}) {
        SCOPED_TRACE(absl::StrCat(
            "key_size = ", key_size,
            ", ciphertext_offset = ", ciphertext_offset,
            ", ciphertext_segment_size = ", ct_segment_size));

        // Construct an encrypter.
        AesGcmHkdfStreamSegmentEncrypter::Params params;
        params.key = Random::GetRandomKeyBytes(key_size);
        params.salt = Random::GetRandomBytes(key_size);
        params.ciphertext_offset = ciphertext_offset;
        params.ciphertext_segment_size = ct_segment_size;
        auto result = AesGcmHkdfStreamSegmentEncrypter::New(params);
        EXPECT_TRUE(result.ok()) << result.status();

        // Use the Constructed encrypter.
        auto enc = std::move(result.value());
        EXPECT_EQ(0, enc->get_segment_number());
        int header_size = key_size + /* nonce_prefix_size = */ 7 + 1;
        EXPECT_EQ(header_size, enc->get_header().size());
        EXPECT_EQ(header_size, enc->get_header()[0]);
        EXPECT_EQ(params.salt, std::string(reinterpret_cast<const char*>(
                                               enc->get_header().data() + 1),
                                           key_size));
        EXPECT_EQ(ct_segment_size, enc->get_ciphertext_segment_size());
        EXPECT_EQ(ct_segment_size - /* tag_size = */ 16,
                  enc->get_plaintext_segment_size());
        EXPECT_EQ(ciphertext_offset, enc->get_ciphertext_offset());
        int segment_number = 0;
        for (int pt_size : {1, 10, enc->get_plaintext_segment_size()}) {
          for (bool is_last_segment : {false, true}) {
            SCOPED_TRACE(absl::StrCat(
                "plaintext_size = ", pt_size,
                ", is_last_segment = ", is_last_segment));
            std::vector<uint8_t> pt(pt_size, 'p');
            std::vector<uint8_t> ct;
            auto status = enc->EncryptSegment(pt, is_last_segment, &ct);
            EXPECT_TRUE(status.ok()) << status;
            EXPECT_EQ(pt_size + /* tag_size = */ 16, ct.size());
            segment_number++;
            EXPECT_EQ(segment_number, enc->get_segment_number());
          }
        }

        // Try encryption with wrong params.
        std::vector<uint8_t> pt(enc->get_plaintext_segment_size() + 1, 'p');
        auto status = enc->EncryptSegment(pt, true, nullptr);
        EXPECT_FALSE(status.ok());
        EXPECT_THAT(std::string(status.message()),
                    HasSubstr("plaintext too long"));
        pt.resize(enc->get_plaintext_segment_size());
        status = enc->EncryptSegment(pt, true, nullptr);
        EXPECT_FALSE(status.ok());
        EXPECT_THAT(std::string(status.message()),
                    HasSubstr("must be non-null"));
      }
    }
  }
}

TEST(AesGcmHkdfStreamSegmentEncrypterTest, testWrongKeySize) {
  for (int key_size : {12, 24, 64}) {
    for (int ciphertext_offset : {0, 5, 10}) {
      for (int ct_segment_size : {128, 200}) {
           SCOPED_TRACE(absl::StrCat(
               "key_size = ", key_size,
               ", ciphertext_offset = ", ciphertext_offset,
               ", ciphertext_segment_size = ", ct_segment_size));
        AesGcmHkdfStreamSegmentEncrypter::Params params;
        params.key = Random::GetRandomKeyBytes(key_size);
        params.salt = Random::GetRandomBytes(key_size);
        params.ciphertext_offset = ciphertext_offset;
        params.ciphertext_segment_size = ct_segment_size;
        auto result = AesGcmHkdfStreamSegmentEncrypter::New(params);
        EXPECT_FALSE(result.ok());
        EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
        EXPECT_THAT(std::string(result.status().message()),
                    HasSubstr("must have 16 or 32 bytes"));
      }
    }
  }
}

TEST(AesGcmHkdfStreamSegmentEncrypterTest, testWrongSaltSize) {
  for (int key_size : {16, 32}) {
    for (int salt_size_delta : {-3, -1, 1, 5, 16}) {
      SCOPED_TRACE(absl::StrCat(
          "key_size = ", key_size,
          ", salt_size = ", key_size + salt_size_delta));
      AesGcmHkdfStreamSegmentEncrypter::Params params;
      params.key = Random::GetRandomKeyBytes(key_size);
      params.salt = Random::GetRandomBytes(key_size + salt_size_delta);
      params.ciphertext_offset = 0;
      params.ciphertext_segment_size = 128;
      auto result = AesGcmHkdfStreamSegmentEncrypter::New(params);
      EXPECT_FALSE(result.ok());
      EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
      EXPECT_THAT(std::string(result.status().message()),
                  HasSubstr("same size as the key"));
    }
  }
}

TEST(AesGcmHkdfStreamSegmentEncrypterTest, testWrongCiphertextOffset) {
  for (int key_size : {16, 32}) {
    for (int ciphertext_offset : {-16, -10, -3, -1}) {
      SCOPED_TRACE(absl::StrCat(
          "key_size = ", key_size,
          ", ciphertext_offset = ", ciphertext_offset));
      AesGcmHkdfStreamSegmentEncrypter::Params params;
      params.key = Random::GetRandomKeyBytes(key_size);
      params.salt = Random::GetRandomBytes(key_size);
      params.ciphertext_offset = ciphertext_offset;
      params.ciphertext_segment_size = 128;
      auto result = AesGcmHkdfStreamSegmentEncrypter::New(params);
      EXPECT_FALSE(result.ok());
      EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
      EXPECT_THAT(std::string(result.status().message()),
                  HasSubstr("must be non-negative"));
    }
  }
}

TEST(AesGcmHkdfStreamSegmentEncrypterTest, testWrongCiphertextSegmentSize) {
  for (int key_size : {16, 32}) {
    for (int ciphertext_offset : {0, 1, 5, 10}) {
      int min_ct_segment_size = key_size + ciphertext_offset +
                                8 +   // nonce_prefix_size + 1
                                16 +   // tag_size
                                1;
      for (int ct_segment_size : {min_ct_segment_size - 5,
              min_ct_segment_size - 1, min_ct_segment_size,
              min_ct_segment_size + 1, min_ct_segment_size + 10}) {
        SCOPED_TRACE(absl::StrCat(
            "key_size = ", key_size,
            ", ciphertext_offset = ", ciphertext_offset,
            ", ciphertext_segment_size = ", ct_segment_size));
        AesGcmHkdfStreamSegmentEncrypter::Params params;
        params.key = Random::GetRandomKeyBytes(key_size);
        params.salt = Random::GetRandomBytes(key_size);
        params.ciphertext_offset = ciphertext_offset;
        params.ciphertext_segment_size = ct_segment_size;
        auto result = AesGcmHkdfStreamSegmentEncrypter::New(params);
        if (ct_segment_size < min_ct_segment_size) {
          EXPECT_FALSE(result.ok());
          EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
          EXPECT_THAT(std::string(result.status().message()),
                      HasSubstr("too small"));
        } else {
          EXPECT_TRUE(result.ok()) << result.status();
        }
      }
    }
  }
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
