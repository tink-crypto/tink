// Copyright 2020 Google LLC
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

#include "tink/cc/cc_streaming_aead_wrappers.h"

#include <utility>

#include "tink/input_stream.h"
#include "tink/output_stream.h"

namespace crypto {
namespace tink {

util::StatusOr<std::unique_ptr<OutputStreamAdapter>> NewCcEncryptingStream(
    StreamingAead* streaming_aead, absl::string_view aad,
    std::shared_ptr<PythonFileObjectAdapter> ciphertext_destination) {
  // Get a destination OutputStream from the destination
  // PythonFileObjectAdapter.
  std::unique_ptr<OutputStream> destination_os =
      absl::make_unique<PythonOutputStream>(ciphertext_destination);

  // Get an EncryptingStream from the destination OutputStream.
  auto result =
      streaming_aead->NewEncryptingStream(std::move(destination_os), aad);
  if (!result.ok()) {
    return result.status();
  }

  // Get an OutputStreamAdapter from the EncryptingStream
  return absl::make_unique<OutputStreamAdapter>(std::move(result.ValueOrDie()));
}

util::StatusOr<std::unique_ptr<InputStreamAdapter>> NewCcDecryptingStream(
    StreamingAead* streaming_aead, absl::string_view aad,
    std::shared_ptr<PythonFileObjectAdapter> ciphertext_source) {
  // Get a source InputStream from the source PythonFileObjectAdapter.
  std::unique_ptr<InputStream> source_os =
      absl::make_unique<PythonInputStream>(ciphertext_source);

  // Get a DecryptingStream from the source InputStream.
  auto result = streaming_aead->NewDecryptingStream(std::move(source_os), aad);
  if (!result.ok()) {
    return result.status();
  }

  // Get an InputStreamAdapter from the DecryptingStream
  return absl::make_unique<InputStreamAdapter>(std::move(result.ValueOrDie()));
}

}  // namespace tink
}  // namespace crypto
