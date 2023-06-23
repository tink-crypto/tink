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

#include "tink/streamingaead/streaming_aead_key_templates.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/streamingaead/aes_ctr_hmac_streaming_key_manager.h"
#include "tink/streamingaead/aes_gcm_hkdf_streaming_key_manager.h"
#include "tink/util/test_matchers.h"
#include "proto/aes_ctr_hmac_streaming.pb.h"
#include "proto/aes_gcm_hkdf_streaming.pb.h"
#include "proto/common.pb.h"
#include "proto/tink.pb.h"

using google::crypto::tink::AesCtrHmacStreamingKeyFormat;
using google::crypto::tink::AesGcmHkdfStreamingKeyFormat;
using google::crypto::tink::HashType;
using google::crypto::tink::KeyTemplate;
using google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::testing::Eq;
using ::testing::Ref;

TEST(Aes128GcmHkdf4KBTest, TypeUrl) {
  EXPECT_THAT(
      StreamingAeadKeyTemplates::Aes128GcmHkdf4KB().type_url(),
      Eq("type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey"));
  EXPECT_THAT(StreamingAeadKeyTemplates::Aes128GcmHkdf4KB().type_url(),
              Eq(AesGcmHkdfStreamingKeyManager().get_key_type()));
}

TEST(Aes128GcmHkdf4KBTest, OutputPrefixType) {
  EXPECT_THAT(
      StreamingAeadKeyTemplates::Aes128GcmHkdf4KB().output_prefix_type(),
      Eq(OutputPrefixType::RAW));
}

TEST(Aes128GcmHkdf4KBTest, SameReference) {
  // Check that reference to the same object is returned.
  EXPECT_THAT(StreamingAeadKeyTemplates::Aes128GcmHkdf4KB(),
              Ref(StreamingAeadKeyTemplates::Aes128GcmHkdf4KB()));
}

TEST(Aes128GcmHkdf4KBTest, WorksWithKeyTypeManager) {
  const KeyTemplate& key_template =
      StreamingAeadKeyTemplates::Aes128GcmHkdf4KB();
  AesGcmHkdfStreamingKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(AesGcmHkdfStreamingKeyManager().ValidateKeyFormat(key_format),
              IsOk());
}

TEST(Aes128GcmHkdf4KBTest, CheckValues) {
  const KeyTemplate& key_template =
      StreamingAeadKeyTemplates::Aes128GcmHkdf4KB();
  AesGcmHkdfStreamingKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(key_format.key_size(), Eq(16));
  EXPECT_THAT(key_format.params().derived_key_size(), Eq(16));
  EXPECT_THAT(key_format.params().ciphertext_segment_size(), Eq(4096));
  EXPECT_THAT(key_format.params().hkdf_hash_type(), Eq(HashType::SHA256));
}

TEST(Aes256GcmHkdf4KBTest, TypeUrl) {
  EXPECT_THAT(
      StreamingAeadKeyTemplates::Aes256GcmHkdf4KB().type_url(),
      Eq("type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey"));
  EXPECT_THAT(StreamingAeadKeyTemplates::Aes256GcmHkdf4KB().type_url(),
              Eq(AesGcmHkdfStreamingKeyManager().get_key_type()));
}

TEST(Aes256GcmHkdf4KBTest, OutputPrefixType) {
  EXPECT_THAT(
      StreamingAeadKeyTemplates::Aes256GcmHkdf4KB().output_prefix_type(),
      Eq(OutputPrefixType::RAW));
}

TEST(Aes256GcmHkdf4KBTest, SameReference) {
  // Check that reference to the same object is returned.
  EXPECT_THAT(StreamingAeadKeyTemplates::Aes256GcmHkdf4KB(),
              Ref(StreamingAeadKeyTemplates::Aes256GcmHkdf4KB()));
}

TEST(Aes256GcmHkdf4KBTest, WorksWithKeyTypeManager) {
  const KeyTemplate& key_template =
      StreamingAeadKeyTemplates::Aes256GcmHkdf4KB();
  AesGcmHkdfStreamingKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(AesGcmHkdfStreamingKeyManager().ValidateKeyFormat(key_format),
              IsOk());
}

TEST(Aes256GcmHkdf4KBTest, CheckValues) {
  const KeyTemplate& key_template =
      StreamingAeadKeyTemplates::Aes256GcmHkdf4KB();
  AesGcmHkdfStreamingKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(key_format.key_size(), Eq(32));
  EXPECT_THAT(key_format.params().derived_key_size(), Eq(32));
  EXPECT_THAT(key_format.params().ciphertext_segment_size(), Eq(4096));
  EXPECT_THAT(key_format.params().hkdf_hash_type(), Eq(HashType::SHA256));
}

TEST(Aes256GcmHkdf1MBTest, TypeUrl) {
  EXPECT_THAT(
      StreamingAeadKeyTemplates::Aes256GcmHkdf1MB().type_url(),
      Eq("type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey"));
  EXPECT_THAT(StreamingAeadKeyTemplates::Aes256GcmHkdf1MB().type_url(),
              Eq(AesGcmHkdfStreamingKeyManager().get_key_type()));
}

TEST(Aes256GcmHkdf1MBTest, OutputPrefixType) {
  EXPECT_THAT(
      StreamingAeadKeyTemplates::Aes256GcmHkdf1MB().output_prefix_type(),
      Eq(OutputPrefixType::RAW));
}

TEST(Aes256GcmHkdf1MBTest, SameReference) {
  // Check that reference to the same object is returned.
  EXPECT_THAT(StreamingAeadKeyTemplates::Aes256GcmHkdf1MB(),
              Ref(StreamingAeadKeyTemplates::Aes256GcmHkdf1MB()));
}

TEST(Aes256GcmHkdf1MBTest, WorksWithKeyTypeManager) {
  const KeyTemplate& key_template =
      StreamingAeadKeyTemplates::Aes256GcmHkdf1MB();
  AesGcmHkdfStreamingKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(AesGcmHkdfStreamingKeyManager().ValidateKeyFormat(key_format),
              IsOk());
}

TEST(Aes256GcmHkdf1MBTest, CheckValues) {
  const KeyTemplate& key_template =
      StreamingAeadKeyTemplates::Aes256GcmHkdf1MB();
  AesGcmHkdfStreamingKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(key_format.key_size(), Eq(32));
  EXPECT_THAT(key_format.params().derived_key_size(), Eq(32));
  EXPECT_THAT(key_format.params().ciphertext_segment_size(), Eq(1048576));
  EXPECT_THAT(key_format.params().hkdf_hash_type(), Eq(HashType::SHA256));
}

TEST(Aes128CtrHmacSha256Segment4KBTest, TypeUrl) {
  EXPECT_THAT(
      StreamingAeadKeyTemplates::Aes128CtrHmacSha256Segment4KB().type_url(),
      Eq("type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey"));
  EXPECT_THAT(
      StreamingAeadKeyTemplates::Aes128CtrHmacSha256Segment4KB().type_url(),
      Eq(AesCtrHmacStreamingKeyManager().get_key_type()));
}

TEST(Aes128CtrHmacSha256Segment4KBTest, OutputPrefixType) {
  EXPECT_THAT(StreamingAeadKeyTemplates::Aes128CtrHmacSha256Segment4KB()
                  .output_prefix_type(),
              Eq(OutputPrefixType::RAW));
}

TEST(Aes128CtrHmacSha256Segment4KBTest, SameReference) {
  // Check that reference to the same object is returned.
  EXPECT_THAT(StreamingAeadKeyTemplates::Aes128CtrHmacSha256Segment4KB(),
              Ref(StreamingAeadKeyTemplates::Aes128CtrHmacSha256Segment4KB()));
}

TEST(Aes128CtrHmacSha256Segment4KBTest, WorksWithKeyTypeManager) {
  const KeyTemplate& key_template =
      StreamingAeadKeyTemplates::Aes128CtrHmacSha256Segment4KB();
  AesCtrHmacStreamingKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKeyFormat(key_format),
              IsOk());
}

TEST(Aes128CtrHmacSha256Segment4KBTest, CheckValues) {
  const KeyTemplate& key_template =
      StreamingAeadKeyTemplates::Aes128CtrHmacSha256Segment4KB();
  AesCtrHmacStreamingKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(key_format.key_size(), Eq(16));
  EXPECT_THAT(key_format.params().ciphertext_segment_size(), Eq(4096));
  EXPECT_THAT(key_format.params().derived_key_size(), Eq(16));
  EXPECT_THAT(key_format.params().hkdf_hash_type(), Eq(HashType::SHA256));
  EXPECT_THAT(key_format.params().hmac_params().hash(), Eq(HashType::SHA256));
  EXPECT_THAT(key_format.params().hmac_params().tag_size(), Eq(32));
}

TEST(Aes128CtrHmacSha256Segment1MBTest, TypeUrl) {
  EXPECT_THAT(
      StreamingAeadKeyTemplates::Aes128CtrHmacSha256Segment1MB().type_url(),
      Eq("type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey"));
  EXPECT_THAT(
      StreamingAeadKeyTemplates::Aes128CtrHmacSha256Segment1MB().type_url(),
      Eq(AesCtrHmacStreamingKeyManager().get_key_type()));
}

TEST(Aes128CtrHmacSha256Segment1MBTest, OutputPrefixType) {
  EXPECT_THAT(StreamingAeadKeyTemplates::Aes128CtrHmacSha256Segment1MB()
                  .output_prefix_type(),
              Eq(OutputPrefixType::RAW));
}

TEST(Aes128CtrHmacSha256Segment1MBTest, SameReference) {
  // Check that reference to the same object is returned.
  EXPECT_THAT(StreamingAeadKeyTemplates::Aes128CtrHmacSha256Segment1MB(),
              Ref(StreamingAeadKeyTemplates::Aes128CtrHmacSha256Segment1MB()));
}

TEST(Aes128CtrHmacSha256Segment1MBTest, WorksWithKeyTypeManager) {
  const KeyTemplate& key_template =
      StreamingAeadKeyTemplates::Aes128CtrHmacSha256Segment1MB();
  AesCtrHmacStreamingKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKeyFormat(key_format),
              IsOk());
}

TEST(Aes128CtrHmacSha256Segment1MBTest, CheckValues) {
  const KeyTemplate& key_template =
      StreamingAeadKeyTemplates::Aes128CtrHmacSha256Segment1MB();
  AesCtrHmacStreamingKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(key_format.key_size(), Eq(16));
  EXPECT_THAT(key_format.params().ciphertext_segment_size(), Eq(1048576));
  EXPECT_THAT(key_format.params().derived_key_size(), Eq(16));
  EXPECT_THAT(key_format.params().hkdf_hash_type(), Eq(HashType::SHA256));
  EXPECT_THAT(key_format.params().hmac_params().hash(), Eq(HashType::SHA256));
  EXPECT_THAT(key_format.params().hmac_params().tag_size(), Eq(32));
}

TEST(Aes256CtrHmacSha256Segment4KBTest, TypeUrl) {
  EXPECT_THAT(
      StreamingAeadKeyTemplates::Aes256CtrHmacSha256Segment4KB().type_url(),
      Eq("type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey"));
  EXPECT_THAT(
      StreamingAeadKeyTemplates::Aes256CtrHmacSha256Segment4KB().type_url(),
      Eq(AesCtrHmacStreamingKeyManager().get_key_type()));
}

TEST(Aes256CtrHmacSha256Segment4KBTest, OutputPrefixType) {
  EXPECT_THAT(StreamingAeadKeyTemplates::Aes256CtrHmacSha256Segment4KB()
                  .output_prefix_type(),
              Eq(OutputPrefixType::RAW));
}

TEST(Aes256CtrHmacSha256Segment4KBTest, SameReference) {
  // Check that reference to the same object is returned.
  EXPECT_THAT(StreamingAeadKeyTemplates::Aes256CtrHmacSha256Segment4KB(),
              Ref(StreamingAeadKeyTemplates::Aes256CtrHmacSha256Segment4KB()));
}

TEST(Aes256CtrHmacSha256Segment4KBTest, WorksWithKeyTypeManager) {
  const KeyTemplate& key_template =
      StreamingAeadKeyTemplates::Aes256CtrHmacSha256Segment4KB();
  AesCtrHmacStreamingKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKeyFormat(key_format),
              IsOk());
}

TEST(Aes256CtrHmacSha256Segment4KBTest, CheckValues) {
  const KeyTemplate& key_template =
      StreamingAeadKeyTemplates::Aes256CtrHmacSha256Segment4KB();
  AesCtrHmacStreamingKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(key_format.key_size(), Eq(32));
  EXPECT_THAT(key_format.params().ciphertext_segment_size(), Eq(4096));
  EXPECT_THAT(key_format.params().derived_key_size(), Eq(32));
  EXPECT_THAT(key_format.params().hkdf_hash_type(), Eq(HashType::SHA256));
  EXPECT_THAT(key_format.params().hmac_params().hash(), Eq(HashType::SHA256));
  EXPECT_THAT(key_format.params().hmac_params().tag_size(), Eq(32));
}

TEST(Aes256CtrHmacSha256Segment1MBTest, TypeUrl) {
  EXPECT_THAT(
      StreamingAeadKeyTemplates::Aes256CtrHmacSha256Segment1MB().type_url(),
      Eq("type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey"));
  EXPECT_THAT(
      StreamingAeadKeyTemplates::Aes256CtrHmacSha256Segment1MB().type_url(),
      Eq(AesCtrHmacStreamingKeyManager().get_key_type()));
}

TEST(Aes256CtrHmacSha256Segment1MBTest, OutputPrefixType) {
  EXPECT_THAT(StreamingAeadKeyTemplates::Aes256CtrHmacSha256Segment1MB()
                  .output_prefix_type(),
              Eq(OutputPrefixType::RAW));
}

TEST(Aes256CtrHmacSha256Segment1MBTest, SameReference) {
  // Check that reference to the same object is returned.
  EXPECT_THAT(StreamingAeadKeyTemplates::Aes256CtrHmacSha256Segment1MB(),
              Ref(StreamingAeadKeyTemplates::Aes256CtrHmacSha256Segment1MB()));
}

TEST(Aes256CtrHmacSha256Segment1MBTest, WorksWithKeyTypeManager) {
  const KeyTemplate& key_template =
      StreamingAeadKeyTemplates::Aes256CtrHmacSha256Segment1MB();
  AesCtrHmacStreamingKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(AesCtrHmacStreamingKeyManager().ValidateKeyFormat(key_format),
              IsOk());
}

TEST(Aes256CtrHmacSha256Segment1MBTest, CheckValues) {
  const KeyTemplate& key_template =
      StreamingAeadKeyTemplates::Aes256CtrHmacSha256Segment1MB();
  AesCtrHmacStreamingKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(key_format.key_size(), Eq(32));
  EXPECT_THAT(key_format.params().ciphertext_segment_size(), Eq(1048576));
  EXPECT_THAT(key_format.params().derived_key_size(), Eq(32));
  EXPECT_THAT(key_format.params().hkdf_hash_type(), Eq(HashType::SHA256));
  EXPECT_THAT(key_format.params().hmac_params().hash(), Eq(HashType::SHA256));
  EXPECT_THAT(key_format.params().hmac_params().tag_size(), Eq(32));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
