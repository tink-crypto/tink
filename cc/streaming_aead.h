// Copyright 2018 Google Inc.
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

#ifndef TINK_STREAMING_AEAD_H_
#define TINK_STREAMING_AEAD_H_

#include <memory>

#include "absl/strings/string_view.h"
#include "tink/input_stream.h"
#include "tink/output_stream.h"
#include "tink/random_access_stream.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {


// An interface for streaming authenticated encryption with associated data.
// Streaming encryption is typically used for encrypting large plaintexts such
// as large files.  Tink may eventually contain multiple interfaces for
// streaming encryption depending on the supported properties. This interface
// supports a streaming interface for symmetric encryption with
// authentication. The underlying encryption modes are selected so that partial
// plaintext can be obtained fast by decrypting and authenticating just a part
// of the ciphertext.
class StreamingAead {
 public:
  // Returns a wrapper around 'ciphertext_destination', such that any bytes
  // written via the wrapper are AEAD-encrypted using 'associated_data' as
  // associated authenticated data. The associated data is not included in the
  // ciphertext and has to be passed in as parameter for decryption.
  // ByteCount() of the wrapper returns the number of written plaintext bytes.
  // Closing the wrapper results in closing of the wrapped stream.
  virtual crypto::tink::util::StatusOr<
      std::unique_ptr<crypto::tink::OutputStream>>
  NewEncryptingStream(
      std::unique_ptr<crypto::tink::OutputStream> ciphertext_destination,
      absl::string_view associated_data) const = 0;

  // Returns a wrapper around 'ciphertext_source', such that reading
  // via the wrapper leads to AEAD-decryption of the underlying ciphertext,
  // using 'associated_data' as associated authenticated data, and the
  // read bytes are bytes of the resulting plaintext.
  // ByteCount() of the wrapper returns the number of read plaintext bytes.
  virtual crypto::tink::util::StatusOr<
      std::unique_ptr<crypto::tink::InputStream>>
  NewDecryptingStream(
      std::unique_ptr<crypto::tink::InputStream> ciphertext_source,
      absl::string_view associated_data) const = 0;

  // Returns a wrapper around 'ciphertext_source', such that reading
  // via the wrapper leads to AEAD-decryption of the underlying ciphertext,
  // using 'associated_data' as associated authenticated data, and the
  // read bytes are bytes of the resulting plaintext.
  // Note that the returned wrapper's size()-method reports size that is
  // not checked for integrity.  For example, if the ciphertext file has been
  // truncated then size() will return a wrong result.  Reading the last block
  // of the plaintext will verify whether size() is correct.
  // Reading through the wrapper is thread safe.
  virtual crypto::tink::util::StatusOr<
      std::unique_ptr<crypto::tink::RandomAccessStream>>
  NewDecryptingRandomAccessStream(
      std::unique_ptr<crypto::tink::RandomAccessStream> ciphertext_source,
      absl::string_view associated_data) const = 0;

  virtual ~StreamingAead() {}
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_STREAMING_AEAD_H_
