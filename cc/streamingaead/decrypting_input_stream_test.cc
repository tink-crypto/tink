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

#include "tink/streamingaead/decrypting_input_stream.h"

#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/input_stream.h"
#include "tink/output_stream.h"
#include "tink/primitive_set.h"
#include "tink/streaming_aead.h"
#include "tink/subtle/random.h"
#include "tink/subtle/test_util.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/ostream_output_stream.h"
#include "tink/util/status.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace streamingaead {
namespace {

using crypto::tink::test::DummyStreamingAead;
using crypto::tink::test::IsOk;
using crypto::tink::test::StatusIs;
using crypto::tink::util::IstreamInputStream;
using crypto::tink::util::OstreamOutputStream;
using google::crypto::tink::KeysetInfo;
using google::crypto::tink::KeyStatusType;
using google::crypto::tink::OutputPrefixType;
using subtle::test::ReadFromStream;
using subtle::test::WriteToStream;

static int kBufferSize = 128;

// Creates an InputStream with the specified contents.
std::unique_ptr<InputStream> GetInputStream(absl::string_view contents) {
  // Prepare ciphertext source stream.
  auto string_stream =
      absl::make_unique<std::stringstream>(std::string(contents));
  std::unique_ptr<InputStream> input_stream(
      absl::make_unique<util::IstreamInputStream>(
          std::move(string_stream), kBufferSize));
  return input_stream;
}

// Creates an InputStream that contains ciphertext resulting
// from encryption of 'pt' with 'aad' as associated data, using 'saead'.
std::unique_ptr<InputStream> GetCiphertextSource(StreamingAead* saead,
                                                 absl::string_view pt,
                                                 absl::string_view aad) {
  // Prepare ciphertext destination stream.
  auto ct_stream = absl::make_unique<std::stringstream>();
  // A reference to the ciphertext buffer.
  auto ct_buf = ct_stream->rdbuf();
  std::unique_ptr<OutputStream> ct_destination(
      absl::make_unique<OstreamOutputStream>(std::move(ct_stream)));

  // Compute the ciphertext.
  auto enc_stream_result =
      saead->NewEncryptingStream(std::move(ct_destination), aad);
  EXPECT_THAT(enc_stream_result, IsOk());
  EXPECT_THAT(WriteToStream(enc_stream_result.value().get(), pt), IsOk());

  // Return the ciphertext as InputStream.
  auto ct_stream3 = absl::make_unique<std::stringstream>(ct_buf->str());
  auto input =  absl::make_unique<IstreamInputStream>(std::move(ct_stream3));
  std::string reads;
  EXPECT_THAT(ReadFromStream(input.get(), &reads), IsOk());
  auto ct_stream2 = absl::make_unique<std::stringstream>(ct_buf->str());
  return absl::make_unique<IstreamInputStream>(std::move(ct_stream2));
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

TEST(DecryptingInputStreamTest, BasicDecryption) {
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
      std::vector<std::unique_ptr<InputStream>> ciphertexts;
      for (const auto& p : *(saead_set->get_raw_primitives().value())) {
        ciphertexts.push_back(
            GetCiphertextSource(&(p->get_primitive()), plaintext, aad));
      }
      EXPECT_EQ(3, ciphertexts.size());

      // Check the decryption of each of the pre-computed ciphertexts.
      for (auto& ct : ciphertexts) {
        // Wrap the primitive set and test the resulting DecryptingInputStream.
        auto dec_stream_result =
            DecryptingInputStream::New(saead_set, std::move(ct), aad);
        EXPECT_THAT(dec_stream_result, IsOk());
        std::string decrypted;
        auto status =
            ReadFromStream(dec_stream_result.value().get(), &decrypted);
        EXPECT_THAT(status, IsOk());
        EXPECT_EQ(plaintext, decrypted);
      }
    }
  }
}

TEST(DecryptingInputStreamTest, WrongAssociatedData) {
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
      auto dec_stream_result =
          DecryptingInputStream::New(saead_set, std::move(ct), "wrong aad");
      EXPECT_THAT(dec_stream_result, IsOk());
      std::string decrypted;
      auto status = ReadFromStream(dec_stream_result.value().get(), &decrypted);
      EXPECT_THAT(status, StatusIs(absl::StatusCode::kInvalidArgument));
    }
  }
}

TEST(DecryptingInputStreamTest, WrongCiphertext) {
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
      auto wrong_ct = GetInputStream(subtle::Random::GetRandomBytes(pt_size));
      auto dec_stream_result =
          DecryptingInputStream::New(saead_set, std::move(wrong_ct), aad);
      EXPECT_THAT(dec_stream_result, IsOk());
      std::string decrypted;
      auto status = ReadFromStream(dec_stream_result.value().get(), &decrypted);
      EXPECT_THAT(status, StatusIs(absl::StatusCode::kInvalidArgument));
    }
  }
}


}  // namespace
}  // namespace streamingaead
}  // namespace tink
}  // namespace crypto
