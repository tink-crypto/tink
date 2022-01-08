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

// Implementation of a StreamingAEAD Service.
#include "streaming_aead_impl.h"

#include "absl/status/status.h"
#include "tink/streaming_aead.h"
#include "tink/binary_keyset_reader.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/util/istream_input_stream.h"
#include "tink/util/ostream_output_stream.h"
#include "tink/util/status.h"
#include "proto/testing/testing_api.grpc.pb.h"

namespace tink_testing_api {

namespace tinkutil = ::crypto::tink::util;

using ::crypto::tink::BinaryKeysetReader;
using ::crypto::tink::CleartextKeysetHandle;
using ::crypto::tink::InputStream;
using ::crypto::tink::util::IstreamInputStream;
using ::crypto::tink::util::OstreamOutputStream;
using ::grpc::ServerContext;
using ::grpc::Status;

// Encrypts a message
::grpc::Status StreamingAeadImpl::Encrypt(
    grpc::ServerContext* context,
    const StreamingAeadEncryptRequest* request,
    StreamingAeadEncryptResponse* response) {
  auto reader_result = BinaryKeysetReader::New(request->keyset());
  if (!reader_result.ok()) {
    response->set_err(std::string(reader_result.status().message()));
    return ::grpc::Status::OK;
  }
  auto handle_result =
      CleartextKeysetHandle::Read(std::move(reader_result.ValueOrDie()));
  if (!handle_result.ok()) {
    response->set_err(std::string(handle_result.status().message()));
    return ::grpc::Status::OK;
  }
  auto streaming_aead_result =
      handle_result.ValueOrDie()->GetPrimitive<crypto::tink::StreamingAead>();
  if (!streaming_aead_result.ok()) {
    response->set_err(std::string(streaming_aead_result.status().message()));
    return ::grpc::Status::OK;
  }

  auto ciphertext_stream = absl::make_unique<std::stringstream>();
  auto ciphertext_buf = ciphertext_stream->rdbuf();
  auto ciphertext_destination(
      absl::make_unique<OstreamOutputStream>(std::move(ciphertext_stream)));

  auto encrypting_stream_result =
      streaming_aead_result.ValueOrDie()->NewEncryptingStream(
          std::move(ciphertext_destination), request->associated_data());
  if (!encrypting_stream_result.ok()) {
    response->set_err(std::string(encrypting_stream_result.status().message()));
    return ::grpc::Status::OK;
  }
  auto encrypting_stream = std::move(encrypting_stream_result.ValueOrDie());

  auto contents = request->plaintext();
  void* buffer;
  int pos = 0;
  int remaining = contents.length();
  int available_space = 0;
  int available_bytes = 0;
  while (remaining > 0) {
    auto next_result = encrypting_stream->Next(&buffer);
    if (!next_result.ok()) {
      response->set_err(std::string(next_result.status().message()));
      return ::grpc::Status::OK;
    }
    available_space = next_result.ValueOrDie();
    available_bytes = std::min(available_space, remaining);
    memcpy(buffer, contents.data() + pos, available_bytes);
    remaining -= available_bytes;
    pos += available_bytes;
  }
  if (available_space > available_bytes) {
    encrypting_stream->BackUp(available_space - available_bytes);
  }
  auto close_status = encrypting_stream->Close();
  if (!close_status.ok()) {
    response->set_err(std::string(close_status.message()));
    return ::grpc::Status::OK;
  }

  response->set_ciphertext(ciphertext_buf->str());
  return ::grpc::Status::OK;
}

// Decrypts a ciphertext
::grpc::Status StreamingAeadImpl::Decrypt(
    grpc::ServerContext* context,
    const StreamingAeadDecryptRequest* request,
    StreamingAeadDecryptResponse* response) {
  auto reader_result = BinaryKeysetReader::New(request->keyset());
  if (!reader_result.ok()) {
    response->set_err(std::string(reader_result.status().message()));
    return ::grpc::Status::OK;
  }
  auto handle_result =
      CleartextKeysetHandle::Read(std::move(reader_result.ValueOrDie()));
  if (!handle_result.ok()) {
    response->set_err(std::string(handle_result.status().message()));
    return ::grpc::Status::OK;
  }
  auto streaming_aead_result =
      handle_result.ValueOrDie()->GetPrimitive<crypto::tink::StreamingAead>();
  if (!streaming_aead_result.ok()) {
    response->set_err(std::string(streaming_aead_result.status().message()));
    return ::grpc::Status::OK;
  }

  auto ciphertext_stream =
      absl::make_unique<std::stringstream>(request->ciphertext());
  std::unique_ptr<InputStream> ciphertext_source(
      absl::make_unique<IstreamInputStream>(std::move(ciphertext_stream)));

  auto decrypting_stream_result =
      streaming_aead_result.ValueOrDie()->NewDecryptingStream(
          std::move(ciphertext_source), request->associated_data());
  if (!decrypting_stream_result.ok()) {
    response->set_err(std::string(decrypting_stream_result.status().message()));
    return ::grpc::Status::OK;
  }
  auto decrypting_stream = std::move(decrypting_stream_result.ValueOrDie());

  std::string plaintext;
  const void* buffer;
  while (true) {
    auto next_result = decrypting_stream->Next(&buffer);
    if (next_result.status().code() == absl::StatusCode::kOutOfRange) {
      // End of stream.
      break;
    }
    if (!next_result.ok()) {
      response->set_err(std::string(next_result.status().message()));
      return ::grpc::Status::OK;
    }
    auto read_bytes = next_result.ValueOrDie();
    if (read_bytes > 0) {
      plaintext.append(
          std::string(reinterpret_cast<const char*>(buffer), read_bytes));
    }
  }

  response->set_plaintext(plaintext);
  return ::grpc::Status::OK;
}

}  // namespace tink_testing_api
