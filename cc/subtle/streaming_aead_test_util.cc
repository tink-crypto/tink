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

#include "tink/subtle/test_util.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/ostream_output_stream.h"
#include "tink/util/status.h"

namespace crypto {
namespace tink {

using ::crypto::tink::util::OstreamOutputStream;
using ::crypto::tink::util::IstreamInputStream;

crypto::tink::util::Status EncryptThenDecrypt(
    StreamingAead* encrypter, StreamingAead* decrypter,
    absl::string_view plaintext, absl::string_view associated_data) {
  // Prepare ciphertext destination stream.
  auto ct_stream = absl::make_unique<std::stringstream>();
  // A reference to the ciphertext buffer, for later validation.
  auto ct_buf = ct_stream->rdbuf();
  auto ct_destination =
      absl::make_unique<OstreamOutputStream>(std::move(ct_stream));

  // Use streaming_aead to encrypt some data.
  auto enc_stream_result = encrypter->NewEncryptingStream(
      std::move(ct_destination), associated_data);
  if (!enc_stream_result.ok()) return enc_stream_result.status();
  auto enc_stream = std::move(enc_stream_result.ValueOrDie());
  auto status = subtle::test::WriteToStream(enc_stream.get(), plaintext);
  if (!status.ok()) return status;
  if (plaintext.size() != enc_stream->Position()) {
    return ::crypto::tink::util::Status(
        crypto::tink::util::error::INTERNAL,
        "Plaintext size different from stream position.");
  }

  auto ct_bytes = absl::make_unique<std::stringstream>(std::string(ct_buf->str()));
  std::unique_ptr<InputStream> ct_source(
      absl::make_unique<IstreamInputStream>(std::move(ct_bytes)));
  auto dec_stream_result = decrypter->NewDecryptingStream(
      std::move(ct_source), associated_data);
  if (!dec_stream_result.ok()) {
    return dec_stream_result.status();
  }
  auto dec_stream = std::move(dec_stream_result.ValueOrDie());
  std::string decrypted;
  status = subtle::test::ReadFromStream(dec_stream.get(), &decrypted);
  if (!status.ok()) {
    return status;
  }
  if (plaintext != decrypted) {
    return ::crypto::tink::util::Status(
        crypto::tink::util::error::INTERNAL,
        "Decryption differs from plaintext, which should never happen.");
  }
  return crypto::tink::util::OkStatus();
}

}  // namespace tink
}  // namespace crypto
