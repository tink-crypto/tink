// Copyright 2019 Google Inc.
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
///////////////////////////////////////////////////////////////////////////////

#include "tink/streamingaead/decrypting_random_access_stream.h"

#include <memory>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/internal/test_random_access_stream.h"
#include "tink/output_stream.h"
#include "tink/primitive_set.h"
#include "tink/random_access_stream.h"
#include "tink/streaming_aead.h"
#include "tink/subtle/random.h"
#include "tink/subtle/test_util.h"
#include "tink/util/buffer.h"
#include "tink/util/ostream_output_stream.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace streamingaead {
namespace {

using crypto::tink::test::DummyStreamingAead;
using crypto::tink::test::IsOk;
using crypto::tink::test::IsOkAndHolds;
using crypto::tink::test::StatusIs;
using google::crypto::tink::KeysetInfo;
using google::crypto::tink::KeyStatusType;
using google::crypto::tink::OutputPrefixType;
using subtle::test::WriteToStream;
using testing::HasSubstr;

// Creates an RandomAccessStream that contains ciphertext resulting
// from encryption of 'pt' with 'aad' as associated data, using 'saead'.
std::unique_ptr<RandomAccessStream> GetCiphertextSource(
    StreamingAead* saead, absl::string_view pt, absl::string_view aad) {
  // Prepare ciphertext destination stream.
  auto ct_stream = absl::make_unique<std::stringstream>();
  // A reference to the ciphertext buffer.
  auto ct_buf = ct_stream->rdbuf();
  std::unique_ptr<OutputStream> ct_destination(
      absl::make_unique<util::OstreamOutputStream>(std::move(ct_stream)));

  // Compute the ciphertext.
  auto enc_stream_result =
      saead->NewEncryptingStream(std::move(ct_destination), aad);
  EXPECT_THAT(enc_stream_result, IsOk());
  EXPECT_THAT(WriteToStream(enc_stream_result.value().get(), pt), IsOk());

  // Return the ciphertext as RandomAccessStream.
  return std::make_unique<internal::TestRandomAccessStream>(ct_buf->str());
}

// A container for specification of instances of DummyStreamingAead
// to be created for testing.
struct StreamingAeadSpec {
  uint32_t key_id;
  std::string saead_name;
};

// Generates a PrimitiveSet<StreamingAead> with DummyStreamingAead
// instances according to the specification in 'spec'.
// The last entry in 'spec' will be the primary primitive in the returned set.
std::shared_ptr<PrimitiveSet<StreamingAead>> GetTestStreamingAeadSet(
    const std::vector<StreamingAeadSpec>& spec) {
  std::shared_ptr<PrimitiveSet<StreamingAead>> saead_set =
      std::make_shared<PrimitiveSet<StreamingAead>>();
  int i = 0;
  for (auto& s : spec) {
    KeysetInfo::KeyInfo key_info;
    key_info.set_output_prefix_type(OutputPrefixType::RAW);
    key_info.set_key_id(s.key_id);
    key_info.set_status(KeyStatusType::ENABLED);
    std::unique_ptr<StreamingAead> saead =
        absl::make_unique<DummyStreamingAead>(s.saead_name);
    auto entry_result = saead_set->AddPrimitive(std::move(saead), key_info);
    EXPECT_TRUE(entry_result.ok());
    if (i + 1 == spec.size()) {
      EXPECT_THAT(saead_set->set_primary(entry_result.value()), IsOk());
    }
    i++;
  }
  return saead_set;
}

TEST(DecryptingRandomAccessStreamTest, BasicDecryption) {
  uint32_t key_id_0 = 1234543;
  uint32_t key_id_1 = 726329;
  uint32_t key_id_2 = 7213743;
  std::string saead_name_0 = "streaming_aead0";
  std::string saead_name_1 = "streaming_aead1";
  std::string saead_name_2 = "streaming_aead2";

  auto saead_set = GetTestStreamingAeadSet(
      {{key_id_0, saead_name_0}, {key_id_1, saead_name_1},
       {key_id_2, saead_name_2}});

  for (int pt_size : {0, 1, 10, 100, 10000}) {
    std::string plaintext = subtle::Random::GetRandomBytes(pt_size);
    for (std::string aad : {"some_aad", "", "some other aad"}) {
      SCOPED_TRACE(absl::StrCat("pt_size = ", pt_size,
                                ", aad = '", aad, "'"));
      // Pre-compute ciphertexts. We create one ciphertext for each primitive
      // in the primitive set, so that we can test decryption with both
      // the primary primitive, and the non-primary ones.
      std::vector<std::unique_ptr<RandomAccessStream>> ciphertexts;
      for (const auto& p : *(saead_set->get_raw_primitives().value())) {
        ciphertexts.push_back(
            GetCiphertextSource(&(p->get_primitive()), plaintext, aad));
      }
      EXPECT_EQ(3, ciphertexts.size());

      // Check the decryption of each of the pre-computed ciphertexts.
      for (auto& ct : ciphertexts) {
        // Wrap the primitive set and test the resulting
        // DecryptingRandomAccessStream.
        auto dec_stream_result =
            DecryptingRandomAccessStream::New(saead_set, std::move(ct), aad);
        EXPECT_THAT(dec_stream_result, IsOk());
        auto dec_stream = std::move(dec_stream_result.value());
        std::string decrypted;
        auto status = internal::ReadAllFromRandomAccessStream(dec_stream.get(),
                                                              decrypted);
        EXPECT_THAT(status, StatusIs(absl::StatusCode::kOutOfRange,
                                     HasSubstr("EOF")));
        EXPECT_EQ(pt_size, dec_stream->size().value());
        EXPECT_EQ(plaintext, decrypted);
      }
    }
  }
}

TEST(DecryptingRandomAccessStreamTest, SelectiveDecryption) {
  uint32_t key_id_0 = 1234543;
  uint32_t key_id_1 = 726329;
  uint32_t key_id_2 = 7213743;
  std::string saead_name_0 = "streaming_aead0";
  std::string saead_name_1 = "streaming_aead1";
  std::string saead_name_2 = "streaming_aead2";

  auto saead_set = GetTestStreamingAeadSet(
      {{key_id_0, saead_name_0}, {key_id_1, saead_name_1},
       {key_id_2, saead_name_2}});

  for (int pt_size : {5, 10, 100, 10000}) {
    std::string plaintext = subtle::Random::GetRandomBytes(pt_size);
    for (std::string aad : {"some_aad", "", "some other aad"}) {
      SCOPED_TRACE(absl::StrCat("pt_size = ", pt_size,
                                ", aad = '", aad, "'"));
      // Pre-compute ciphertexts. We create one ciphertext for each primitive
      // in the primitive set, so that we can test decryption with both
      // the primary primitive, and the non-primary ones.
      std::vector<std::unique_ptr<RandomAccessStream>> ciphertexts;
      for (const auto& p : *(saead_set->get_raw_primitives().value())) {
        ciphertexts.push_back(
            GetCiphertextSource(&(p->get_primitive()), plaintext, aad));
      }
      EXPECT_EQ(3, ciphertexts.size());

      // Check the decryption of each of the pre-computed ciphertexts.
      int ct_number = 0;
      for (auto& ct : ciphertexts) {
        // Wrap the primitive set and test the resulting
        // DecryptingRandomAccessStream.
        auto dec_stream_result =
            DecryptingRandomAccessStream::New(saead_set, std::move(ct), aad);
        EXPECT_THAT(dec_stream_result, IsOk());
        auto dec_stream = std::move(dec_stream_result.value());
        for (int position : {0, 1, 2, pt_size/2, pt_size-1}) {
          for (int chunk_size : {1, pt_size/2, pt_size}) {
            SCOPED_TRACE(absl::StrCat("ct_number = ", ct_number,
                                      ", position = ", position,
                                      ", chunk_size = ", chunk_size));
            auto buffer = std::move(util::Buffer::New(chunk_size).value());
            util::Status status =
                dec_stream->PRead(position, chunk_size, buffer.get());
            EXPECT_THAT(status,
                        testing::AnyOf(
                            IsOk(), StatusIs(absl::StatusCode::kOutOfRange)));
            EXPECT_EQ(std::min(chunk_size, pt_size - position), buffer->size());
            EXPECT_EQ(0, std::memcmp(plaintext.data() + position,
                                     buffer->get_mem_block(), buffer->size()));
          }
        }
        ct_number++;
      }
    }
  }
}

TEST(DecryptingRandomAccessStreamTest, OutOfRangeDecryption) {
  uint32_t key_id_0 = 1234543;
  uint32_t key_id_1 = 726329;
  uint32_t key_id_2 = 7213743;
  std::string saead_name_0 = "streaming_aead0";
  std::string saead_name_1 = "streaming_aead1";
  std::string saead_name_2 = "streaming_aead2";

  auto saead_set = GetTestStreamingAeadSet(
      {{key_id_0, saead_name_0}, {key_id_1, saead_name_1},
       {key_id_2, saead_name_2}});

  for (int pt_size : {1, 5, 10, 100, 10000}) {
    std::string plaintext = subtle::Random::GetRandomBytes(pt_size);
    for (std::string aad : {"some_aad", "", "some other aad"}) {
      SCOPED_TRACE(absl::StrCat("pt_size = ", pt_size,
                                ", aad = '", aad, "'"));
      // Pre-compute ciphertexts. We create one ciphertext for each primitive
      // in the primitive set, so that we can test decryption with both
      // the primary primitive, and the non-primary ones.
      std::vector<std::unique_ptr<RandomAccessStream>> ciphertexts;
      for (const auto& p : *(saead_set->get_raw_primitives().value())) {
        ciphertexts.push_back(
            GetCiphertextSource(&(p->get_primitive()), plaintext, aad));
      }
      EXPECT_EQ(3, ciphertexts.size());

      // Check the decryption of each of the pre-computed ciphertexts.
      int ct_number = 0;
      for (auto& ct : ciphertexts) {
        // Wrap the primitive set and test the resulting
        // DecryptingRandomAccessStream.
        auto dec_stream_result =
            DecryptingRandomAccessStream::New(saead_set, std::move(ct), aad);
        EXPECT_THAT(dec_stream_result, IsOk());
        auto dec_stream = std::move(dec_stream_result.value());
        int chunk_size = 1;
        auto buffer = std::move(util::Buffer::New(chunk_size).value());
        for (int position : {pt_size, pt_size + 1}) {
          SCOPED_TRACE(absl::StrCat("ct_number = ", ct_number,
                                    ", position = ", position));
          // Negative chunk size.
          auto status = dec_stream->PRead(position, -1, buffer.get());
          EXPECT_THAT(status, StatusIs(absl::StatusCode::kInvalidArgument));

          // Negative position.
          status = dec_stream->PRead(-1, chunk_size, buffer.get());
          EXPECT_THAT(status, StatusIs(absl::StatusCode::kInvalidArgument));

          // Reading past EOF.
          status = dec_stream->PRead(position, chunk_size, buffer.get());
          EXPECT_THAT(status, StatusIs(absl::StatusCode::kOutOfRange));
        }
        ct_number++;
      }
    }
  }
}

TEST(DecryptingRandomAccessStreamTest, WrongAssociatedData) {
  uint32_t key_id_0 = 1234543;
  uint32_t key_id_1 = 726329;
  uint32_t key_id_2 = 7213743;
  std::string saead_name_0 = "streaming_aead0";
  std::string saead_name_1 = "streaming_aead1";
  std::string saead_name_2 = "streaming_aead2";

  auto saead_set = GetTestStreamingAeadSet(
      {{key_id_0, saead_name_0}, {key_id_1, saead_name_1},
       {key_id_2, saead_name_2}});

  for (int pt_size : {0, 1, 10, 100, 10000}) {
    std::string plaintext = subtle::Random::GetRandomBytes(pt_size);
    for (std::string aad : {"some_aad", "", "some other aad"}) {
      SCOPED_TRACE(absl::StrCat("pt_size = ", pt_size,
                                ", aad = '", aad, "'"));
      // Compute a ciphertext with the primary primitive.
      auto ct = GetCiphertextSource(
          &(saead_set->get_primary()->get_primitive()), plaintext, aad);
      auto dec_stream_result = DecryptingRandomAccessStream::New(
          saead_set, std::move(ct), "wrong aad");
      EXPECT_THAT(dec_stream_result, IsOk());
      std::string decrypted;
      auto status = internal::ReadAllFromRandomAccessStream(
          dec_stream_result.value().get(), decrypted);
      EXPECT_THAT(status, StatusIs(absl::StatusCode::kInvalidArgument));
    }
  }
}

TEST(DecryptingRandomAccessStreamTest, WrongCiphertext) {
  uint32_t key_id_0 = 1234543;
  uint32_t key_id_1 = 726329;
  uint32_t key_id_2 = 7213743;
  std::string saead_name_0 = "streaming_aead0";
  std::string saead_name_1 = "streaming_aead1";
  std::string saead_name_2 = "streaming_aead2";

  auto saead_set = GetTestStreamingAeadSet(
      {{key_id_0, saead_name_0}, {key_id_1, saead_name_1},
       {key_id_2, saead_name_2}});

  for (int pt_size : {0, 1, 10, 100, 10000}) {
    std::string plaintext = subtle::Random::GetRandomBytes(pt_size);
    for (std::string aad : {"some_aad", "", "some other aad"}) {
      SCOPED_TRACE(absl::StrCat("pt_size = ", pt_size,
                                ", aad = '", aad, "'"));
      // Try decrypting a wrong ciphertext.
      auto wrong_ct = std::make_unique<internal::TestRandomAccessStream>(
          subtle::Random::GetRandomBytes(pt_size));
      auto dec_stream_result = DecryptingRandomAccessStream::New(
          saead_set, std::move(wrong_ct), aad);
      EXPECT_THAT(dec_stream_result, IsOk());
      std::string decrypted;
      auto status = internal::ReadAllFromRandomAccessStream(
          dec_stream_result.value().get(), decrypted);
      EXPECT_THAT(status, StatusIs(absl::StatusCode::kInvalidArgument));
    }
  }
}

TEST(DecryptingRandomAccessStreamTest, NullPrimitiveSet) {
  auto ct_stream = std::make_unique<internal::TestRandomAccessStream>(
      "some ciphertext contents");
  auto dec_stream_result = DecryptingRandomAccessStream::New(
          nullptr, std::move(ct_stream), "some aad");
  EXPECT_THAT(dec_stream_result.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("primitives must be non-null")));
}

TEST(DecryptingRandomAccessStreamTest, NullCiphertextSource) {
  uint32_t key_id = 1234543;
  std::string saead_name = "streaming_aead";
  auto saead_set = GetTestStreamingAeadSet({{key_id, saead_name}});

  auto dec_stream_result = DecryptingRandomAccessStream::New(
      saead_set, nullptr, "some aad");
  EXPECT_THAT(dec_stream_result.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("ciphertext_source must be non-null")));
}

TEST(DecryptingRandomAccessStreamTest, CallSizeBeforePReadWorks) {
  uint32_t key_id = 1234543;
  std::string saead_name = "streaming_aead";
  auto saead_set = GetTestStreamingAeadSet({{key_id, saead_name}});

  std::string associated_data = "associated_data";

  for (int pt_size : {0, 1, 100}) {
    std::string plaintext = subtle::Random::GetRandomBytes(pt_size);
    std::unique_ptr<RandomAccessStream> ciphertext =
        GetCiphertextSource(&(saead_set->get_primary()->get_primitive()),
                            plaintext, associated_data);

    util::StatusOr<std::unique_ptr<RandomAccessStream>> dec_stream =
        DecryptingRandomAccessStream::New(saead_set, std::move(ciphertext),
                                          associated_data);
    ASSERT_THAT(dec_stream, IsOk());
    EXPECT_THAT((*dec_stream)->size(), IsOkAndHolds(pt_size));
  }
}

}  // namespace
}  // namespace streamingaead
}  // namespace tink
}  // namespace crypto
