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
#include "tink/subtle/streaming_aead_test_util.h"

#include <sstream>
#include <string>

#include "tink/random_access_stream.h"
#include "tink/subtle/test_util.h"
#include "tink/util/buffer.h"
#include "tink/util/file_random_access_stream.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/ostream_output_stream.h"
#include "tink/util/status.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {

using ::crypto::tink::test::GetTestFileDescriptor;
using ::crypto::tink::util::IstreamInputStream;
using ::crypto::tink::util::OstreamOutputStream;
using ::crypto::tink::util::Status;

namespace {

// Creates a RandomAccessStream with the specified contents.
std::unique_ptr<RandomAccessStream> GetRandomAccessStreamContaining(
    absl::string_view contents) {
  static int index = 1;
  std::string filename = absl::StrCat("stream_data_file_", index, ".txt");
  index++;
  int input_fd = GetTestFileDescriptor(filename, contents);
  return {absl::make_unique<util::FileRandomAccessStream>(input_fd)};
}

// Reads up to 'count' bytes from 'ras' starting at position 'pos'
// and verifies that the read bytes are equal to the corresponding
// subsequence in 'full_contents'.
Status ReadAndVerifyFragment(RandomAccessStream* ras, int pos, int count,
                             absl::string_view full_contents) {
  auto buf_result = util::Buffer::New(count);
  if (!buf_result.ok()) {
    return Status(absl::StatusCode::kInternal,
                  absl::StrCat("Could not allocate buffer of size ", count));
  }
  auto buf = std::move(buf_result.ValueOrDie());
  int full_size = full_contents.size();
  auto status = ras->PRead(pos, count, buf.get());
  if (!status.ok() && status.code() != absl::StatusCode::kOutOfRange) {
    return Status(
        absl::StatusCode::kInternal,
        absl::StrCat("PRead failed with status: ", status.ToString()));
  }
  int exp_size = std::min(count, full_size - pos);
  if (exp_size != buf->size()) {
    return Status(absl::StatusCode::kInternal,
                  absl::StrCat("PRead returned ", buf->size(), " bytes, while ",
                               exp_size, " bytes were expected."));
  }
  if (std::memcmp(full_contents.data() + pos, buf->get_mem_block(), exp_size)) {
    return Status(
        absl::StatusCode::kInternal,
        absl::StrCat("PRead returned bytes [",
                     std::string(buf->get_mem_block(), exp_size), "] while [",
                     full_contents.substr(pos, exp_size), "] were expected."));
  }
  return util::OkStatus();
}

}  // namespace

crypto::tink::util::Status EncryptThenDecrypt(StreamingAead* encrypter,
                                              StreamingAead* decrypter,
                                              absl::string_view plaintext,
                                              absl::string_view associated_data,
                                              int ciphertext_offset) {
  // Prepare ciphertext destination stream.
  auto ct_stream = absl::make_unique<std::stringstream>();

  // A reference to the ciphertext buffer, for later validation.
  auto ct_buf = ct_stream->rdbuf();
  auto ct_destination =
      absl::make_unique<OstreamOutputStream>(std::move(ct_stream));
  auto status = subtle::test::WriteToStream(
      ct_destination.get(), std::string(ciphertext_offset, 'o'), false);
  if (!status.ok()) return status;

  // Use encrypter to encrypt some data.
  auto enc_stream_result = encrypter->NewEncryptingStream(
      std::move(ct_destination), associated_data);
  if (!enc_stream_result.ok()) return enc_stream_result.status();
  auto enc_stream = std::move(enc_stream_result.ValueOrDie());
  status = subtle::test::WriteToStream(enc_stream.get(), plaintext);
  if (!status.ok()) return status;
  if (plaintext.size() != enc_stream->Position()) {
    return ::crypto::tink::util::Status(
        absl::StatusCode::kInternal,
        "Plaintext size different from stream position.");
  }

  // Prepare an InputStream with the ciphertext.
  auto ct_bytes = absl::make_unique<std::stringstream>(
      ct_buf->str().substr(ciphertext_offset));
  std::unique_ptr<InputStream> ct_source(
      absl::make_unique<IstreamInputStream>(std::move(ct_bytes)));

  // Decrypt the ciphertext using the decrypter.
  auto dec_stream_result = decrypter->NewDecryptingStream(
      std::move(ct_source), associated_data);
  if (!dec_stream_result.ok()) return dec_stream_result.status();
  auto dec_stream = std::move(dec_stream_result.ValueOrDie());
  std::string decrypted;
  status = subtle::test::ReadFromStream(dec_stream.get(), &decrypted);
  if (!status.ok()) {
    return status;
  }
  if (plaintext != decrypted) {
    return ::crypto::tink::util::Status(absl::StatusCode::kInternal,
                                        "Decryption differs from plaintext.");
  }

  // Prepare a RandomAccessStream with the ciphertext.
  auto ct_ras = GetRandomAccessStreamContaining(std::string(ct_buf->str()));

  // Decrypt fragments of the ciphertext using the decrypter.
  auto dec_ras_result = decrypter->NewDecryptingRandomAccessStream(
      std::move(ct_ras), associated_data);
  if (!dec_ras_result.ok()) return dec_ras_result.status();
  auto dec_ras = std::move(dec_ras_result.ValueOrDie());
  int pt_size = plaintext.size();
  for (int pos : {0, pt_size / 2, std::max(pt_size - 10, 0)}) {
    for (int count : {1, 10, std::max(pt_size / 2, 1), std::max(pt_size, 1)}) {
      auto status = ReadAndVerifyFragment(dec_ras.get(), pos, count, plaintext);
      if (!status.ok()) {
        return Status(
            absl::StatusCode::kInternal,
            absl::StrCat("Random access decryption failed at position=", pos,
                         " with count=", count,
                         " and status: ", status.ToString()));
      }
    }
  }
  return crypto::tink::util::OkStatus();
}

}  // namespace tink
}  // namespace crypto
