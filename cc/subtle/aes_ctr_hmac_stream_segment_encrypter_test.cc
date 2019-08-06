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

#include "tink/subtle/aes_ctr_hmac_stream_segment_encrypter.h"

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/random.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

using ::crypto::tink::test::StatusIs;
using ::testing::HasSubstr;

namespace crypto {
namespace tink {
namespace subtle {
namespace {

TEST(AesCtrHmacStreamSegmentEncrypterTest, Basic) {
  for (int key_size : {16, 32}) {
    for (int ciphertext_offset : {0, 5, 10}) {
      for (int ct_segment_size : {80, 128, 200}) {
        for (HashType tag_algo : {SHA1, SHA256, SHA512}) {
          for (int tag_size : {10, 16, 20}) {
            SCOPED_TRACE(
                absl::StrCat("key_size = ", key_size,
                             ", ciphertext_offset = ", ciphertext_offset,
                             ", ciphertext_segment_size = ", ct_segment_size,
                             ", tag_algo = ", EnumToString(tag_algo),
                             ", tag_size = ", tag_size));

            // Construct an encrypter.
            AesCtrHmacStreamSegmentEncrypter::Params params;
            params.key_value = Random::GetRandomBytes(key_size);
            params.salt = Random::GetRandomBytes(key_size);
            params.ciphertext_offset = ciphertext_offset;
            params.ciphertext_segment_size = ct_segment_size;
            params.tag_algo = tag_algo;
            params.tag_size = tag_size;
            params.hmac_key_value = Random::GetRandomBytes(32);
            auto result = AesCtrHmacStreamSegmentEncrypter::New(params);
            EXPECT_TRUE(result.ok()) << result.status();

            // Use the Constructed encrypter.
            auto enc = std::move(result.ValueOrDie());
            EXPECT_EQ(0, enc->get_segment_number());
            int header_size = key_size + /* nonce_prefix_size = */ 7 + 1;
            EXPECT_EQ(header_size, enc->get_header().size());
            EXPECT_EQ(header_size, enc->get_header()[0]);
            EXPECT_EQ(params.salt, std::string(reinterpret_cast<const char*>(
                                              enc->get_header().data() + 1),
                                          key_size));
            EXPECT_EQ(ct_segment_size, enc->get_ciphertext_segment_size());
            EXPECT_EQ(ct_segment_size - tag_size,
                      enc->get_plaintext_segment_size());
            EXPECT_EQ(ciphertext_offset, enc->get_ciphertext_offset());

            int segment_number = 0;
            for (int pt_size : {1, 10, enc->get_plaintext_segment_size()}) {
              for (bool is_last_segment : {false, true}) {
                SCOPED_TRACE(
                    absl::StrCat("plaintext_size = ", pt_size,
                                 ", is_last_segment = ", is_last_segment));
                std::vector<uint8_t> pt(pt_size, 'p');
                std::vector<uint8_t> ct;
                auto status = enc->EncryptSegment(pt, is_last_segment, &ct);
                EXPECT_TRUE(status.ok()) << status;
                EXPECT_EQ(pt_size + tag_size, ct.size());
                segment_number++;
                EXPECT_EQ(segment_number, enc->get_segment_number());
              }
            }

            // Try encryption with wrong params.
            std::vector<uint8_t> pt(enc->get_plaintext_segment_size() + 1, 'p');
            EXPECT_THAT(enc->EncryptSegment(pt, true, nullptr),
                        StatusIs(util::error::INVALID_ARGUMENT,
                                 HasSubstr("plaintext too long")));
            pt.resize(enc->get_plaintext_segment_size());
            EXPECT_THAT(enc->EncryptSegment(pt, true, nullptr),
                        StatusIs(util::error::INVALID_ARGUMENT,
                                 HasSubstr("must be non-nul")));
          }
        }
      }
    }
  }
}

TEST(AesCtrHmacStreamSegmentEncrypterTest, WrongKeySize) {
  for (int key_size : {12, 24, 64}) {
    SCOPED_TRACE(absl::StrCat("key_size = ", key_size));

    AesCtrHmacStreamSegmentEncrypter::Params params;
    params.key_value = Random::GetRandomBytes(key_size);
    params.salt = Random::GetRandomBytes(key_size);
    params.ciphertext_offset = 0;
    params.ciphertext_segment_size = 128;
    params.tag_algo = SHA256;
    params.tag_size = 16;
    params.hmac_key_value = Random::GetRandomBytes(32);

    EXPECT_THAT(AesCtrHmacStreamSegmentEncrypter::New(params).status(),
                StatusIs(util::error::INVALID_ARGUMENT,
                         HasSubstr("must have 16 or 32 bytes")));
  }
}

TEST(AesCtrHmacStreamSegmentEncrypterTest, WrongSaltSize) {
  for (int key_size : {16, 32}) {
    for (int salt_size_delta : {-3, -1, 1, 5, 16}) {
      SCOPED_TRACE(absl::StrCat(
          "key_size = ", key_size,
          ", salt_size = ", key_size + salt_size_delta));
      AesCtrHmacStreamSegmentEncrypter::Params params;
      params.key_value = Random::GetRandomBytes(key_size);
      params.salt = Random::GetRandomBytes(key_size + salt_size_delta);
      params.ciphertext_offset = 0;
      params.ciphertext_segment_size = 128;
      params.tag_algo = SHA256;
      params.tag_size = 16;
      params.hmac_key_value = Random::GetRandomBytes(32);

      EXPECT_THAT(AesCtrHmacStreamSegmentEncrypter::New(params).status(),
                  StatusIs(util::error::INVALID_ARGUMENT,
                           HasSubstr("same size as key_value")));
    }
  }
}

TEST(AesCtrHmacStreamSegmentEncrypterTest, WrongCiphertextOffset) {
  for (int key_size : {16, 32}) {
    for (int ciphertext_offset : {-16, -10, -3, -1}) {
      SCOPED_TRACE(absl::StrCat(
          "key_size = ", key_size,
          ", ciphertext_offset = ", ciphertext_offset));
      AesCtrHmacStreamSegmentEncrypter::Params params;
      params.key_value = Random::GetRandomBytes(key_size);
      params.salt = Random::GetRandomBytes(key_size);
      params.ciphertext_offset = ciphertext_offset;
      params.ciphertext_segment_size = 128;
      params.tag_algo = SHA256;
      params.tag_size = 16;
      params.hmac_key_value = Random::GetRandomBytes(32);

      EXPECT_THAT(AesCtrHmacStreamSegmentEncrypter::New(params).status(),
                  StatusIs(util::error::INVALID_ARGUMENT,
                           HasSubstr("must be non-negative")));
    }
  }
}

TEST(AesCtrHmacStreamSegmentEncrypterTest, WrongCiphertextSegmentSize) {
  for (int key_size : {16, 32}) {
    for (int tag_size : {10, 16, 32}) {
      for (int ciphertext_offset : {0, 1, 5, 10}) {
        int min_ct_segment_size = key_size + ciphertext_offset +
                                  8 +  // nonce_prefix_size + 1
                                  tag_size;
        for (int ct_segment_size :
             {min_ct_segment_size - 5, min_ct_segment_size - 1,
              min_ct_segment_size, min_ct_segment_size + 1,
              min_ct_segment_size + 10}) {
          SCOPED_TRACE(
              absl::StrCat("key_size = ", key_size, ", tag_size = ", tag_size,
                           ", ciphertext_offset = ", ciphertext_offset,
                           ", ciphertext_segment_size = ", ct_segment_size));

          AesCtrHmacStreamSegmentEncrypter::Params params;
          params.key_value = Random::GetRandomBytes(key_size);
          params.salt = Random::GetRandomBytes(key_size);
          params.ciphertext_offset = ciphertext_offset;
          params.ciphertext_segment_size = ct_segment_size;
          params.tag_algo = SHA256;
          params.tag_size = tag_size;
          params.hmac_key_value = Random::GetRandomBytes(32);

          auto result = AesCtrHmacStreamSegmentEncrypter::New(params);
          if (ct_segment_size < min_ct_segment_size) {
            EXPECT_THAT(result.status(), StatusIs(util::error::INVALID_ARGUMENT,
                                                  HasSubstr("too small")));
          } else {
            EXPECT_TRUE(result.ok()) << result.status();
          }
        }
      }
    }
  }
}

TEST(AesCtrHmacStreamSegmentEncrypterTest, WrongHmacKeySize) {
  for (int hmac_key_size : {12, 24, 64}) {
    SCOPED_TRACE(absl::StrCat("hmac_key_size = ", hmac_key_size));

    AesCtrHmacStreamSegmentEncrypter::Params params;
    params.key_value = Random::GetRandomBytes(16);
    params.salt = Random::GetRandomBytes(16);
    params.ciphertext_offset = 0;
    params.ciphertext_segment_size = 128;
    params.tag_algo = SHA256;
    params.tag_size = 16;
    params.hmac_key_value = Random::GetRandomBytes(hmac_key_size);

    EXPECT_THAT(AesCtrHmacStreamSegmentEncrypter::New(params).status(),
                StatusIs(util::error::INVALID_ARGUMENT,
                         HasSubstr("invalid hmac_key_value size")));
  }
}

TEST(AesCtrHmacStreamSegmentEncrypterTest, WrongHashAlgo) {
  for (HashType tag_algo : {SHA384, UNKNOWN_HASH}) {
    SCOPED_TRACE(absl::StrCat("tag_algo = ", EnumToString(tag_algo)));

    AesCtrHmacStreamSegmentEncrypter::Params params;
    params.key_value = Random::GetRandomBytes(16);
    params.salt = Random::GetRandomBytes(16);
    params.ciphertext_offset = 0;
    params.ciphertext_segment_size = 128;
    params.tag_algo = tag_algo;
    params.tag_size = 16;
    params.hmac_key_value = Random::GetRandomBytes(32);

    EXPECT_THAT(AesCtrHmacStreamSegmentEncrypter::New(params).status(),
                StatusIs(util::error::INVALID_ARGUMENT,
                         HasSubstr("unsupported hash algo")));
  }
}

TEST(AesCtrHmacStreamSegmentEncrypterTest, WrongTagSize) {
  for (HashType tag_algo : {SHA1, SHA256, SHA512}) {
    for (int tag_size : {5, 10, 20, 30, 32, 60, 64, 100}) {
      SCOPED_TRACE(absl::StrCat("tag_algo = ", EnumToString(tag_algo),
                                ", tag_size = ", tag_size));

      AesCtrHmacStreamSegmentEncrypter::Params params;
      params.key_value = Random::GetRandomBytes(16);
      params.salt = Random::GetRandomBytes(16);
      params.ciphertext_offset = 0;
      params.ciphertext_segment_size = 128;
      params.tag_algo = tag_algo;
      params.tag_size = tag_size;
      params.hmac_key_value = Random::GetRandomBytes(32);
      auto result = AesCtrHmacStreamSegmentEncrypter::New(params);

      if (tag_size < 10) {
        EXPECT_THAT(result.status(), StatusIs(util::error::INVALID_ARGUMENT,
                                              HasSubstr("tag size too small")));
      } else if ((tag_algo == SHA1 && tag_size > 20) ||
                 (tag_algo == SHA256 && tag_size > 32) ||
                 (tag_algo == SHA512 && tag_size > 64)) {
        EXPECT_THAT(result.status(), StatusIs(util::error::INVALID_ARGUMENT,
                                              HasSubstr("tag size too big")));
      } else {
        EXPECT_TRUE(result.ok()) << result.status();
      }
    }
  }
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
