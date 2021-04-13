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

// Implementation of a Keyset Service.
#include "keyset_impl.h"

#include "tink/binary_keyset_reader.h"
#include "tink/binary_keyset_writer.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/json_keyset_reader.h"
#include "tink/json_keyset_writer.h"
#include "tink/keyset_handle.h"
#include "proto/tink.pb.h"

namespace tink_testing_api {

using ::crypto::tink::BinaryKeysetReader;
using ::crypto::tink::BinaryKeysetWriter;
using ::crypto::tink::CleartextKeysetHandle;
using ::crypto::tink::JsonKeysetReader;
using ::crypto::tink::JsonKeysetWriter;
using ::crypto::tink::KeysetHandle;
using ::google::crypto::tink::KeyTemplate;
using ::grpc::ServerContext;
using ::grpc::Status;

// Generates a new keyset with one key from a template.
::grpc::Status KeysetImpl::Generate(grpc::ServerContext* context,
                                    const KeysetGenerateRequest* request,
                                    KeysetGenerateResponse* response) {
  KeyTemplate key_template;
  if (!key_template.ParseFromString(request->template_())) {
    response->set_err("Could not parse the key template");
    return ::grpc::Status::OK;
  }
  auto handle_result = KeysetHandle::GenerateNew(key_template);
  if (!handle_result.ok()) {
    response->set_err(handle_result.status().error_message());
    return ::grpc::Status::OK;
  }
  std::stringbuf keyset;
  auto writer_result =
      BinaryKeysetWriter::New(absl::make_unique<std::ostream>(&keyset));
  if (!writer_result.ok()) {
    response->set_err(writer_result.status().error_message());
    return ::grpc::Status::OK;
  }
  auto status = CleartextKeysetHandle::Write(writer_result.ValueOrDie().get(),
                                             *handle_result.ValueOrDie());
  if (!status.ok()) {
    response->set_err(status.error_message());
    return ::grpc::Status::OK;
  }
  response->set_keyset(keyset.str());
  return ::grpc::Status::OK;
}

// Returns a public keyset for a given private keyset.
::grpc::Status KeysetImpl::Public(grpc::ServerContext* context,
                                  const KeysetPublicRequest* request,
                                  KeysetPublicResponse* response) {
  auto reader_result = BinaryKeysetReader::New(request->private_keyset());
  if (!reader_result.ok()) {
    response->set_err(reader_result.status().error_message());
    return ::grpc::Status::OK;
  }
  auto private_handle_result =
      CleartextKeysetHandle::Read(std::move(reader_result.ValueOrDie()));
  if (!private_handle_result.ok()) {
    response->set_err(private_handle_result.status().error_message());
    return ::grpc::Status::OK;
  }
  auto public_handle_result =
      private_handle_result.ValueOrDie()->GetPublicKeysetHandle();
  if (!public_handle_result.ok()) {
    response->set_err(public_handle_result.status().error_message());
    return ::grpc::Status::OK;
  }
  std::stringbuf public_keyset;
  auto writer_result =
      BinaryKeysetWriter::New(absl::make_unique<std::ostream>(&public_keyset));
  if (!writer_result.ok()) {
    response->set_err(writer_result.status().error_message());
    return ::grpc::Status::OK;
  }
  auto status = CleartextKeysetHandle::Write(
      writer_result.ValueOrDie().get(), *public_handle_result.ValueOrDie());
  if (!status.ok()) {
    response->set_err(status.error_message());
    return ::grpc::Status::OK;
  }
  response->set_public_keyset(public_keyset.str());
  return ::grpc::Status::OK;
}

// Converts a keyset from binary to JSON format.
::grpc::Status KeysetImpl::ToJson(grpc::ServerContext* context,
                                  const KeysetToJsonRequest* request,
                                  KeysetToJsonResponse* response) {
  auto reader_result = BinaryKeysetReader::New(request->keyset());
  if (!reader_result.ok()) {
    response->set_err(reader_result.status().error_message());
    return ::grpc::Status::OK;
  }
  auto handle_result =
      CleartextKeysetHandle::Read(std::move(reader_result.ValueOrDie()));
  if (!handle_result.ok()) {
    response->set_err(handle_result.status().error_message());
    return ::grpc::Status::OK;
  }
  std::stringbuf json_keyset;
  auto writer_result =
      JsonKeysetWriter::New(absl::make_unique<std::ostream>(&json_keyset));
  if (!writer_result.ok()) {
    response->set_err(writer_result.status().error_message());
    return ::grpc::Status::OK;
  }
  auto status = CleartextKeysetHandle::Write(writer_result.ValueOrDie().get(),
                                             *handle_result.ValueOrDie());
  if (!status.ok()) {
    response->set_err(status.error_message());
    return ::grpc::Status::OK;
  }
  response->set_json_keyset(json_keyset.str());
  return ::grpc::Status::OK;
}

// Converts a keyset from JSON to binary format.
::grpc::Status KeysetImpl::FromJson(grpc::ServerContext* context,
                                    const KeysetFromJsonRequest* request,
                                    KeysetFromJsonResponse* response) {
  auto reader_result = JsonKeysetReader::New(request->json_keyset());
  if (!reader_result.ok()) {
    response->set_err(reader_result.status().error_message());
    return ::grpc::Status::OK;
  }
  auto handle_result =
      CleartextKeysetHandle::Read(std::move(reader_result.ValueOrDie()));
  if (!handle_result.ok()) {
    response->set_err(handle_result.status().error_message());
    return ::grpc::Status::OK;
  }
  std::stringbuf keyset;
  auto writer_result =
      BinaryKeysetWriter::New(absl::make_unique<std::ostream>(&keyset));
  if (!writer_result.ok()) {
    response->set_err(writer_result.status().error_message());
    return ::grpc::Status::OK;
  }
  auto status = CleartextKeysetHandle::Write(writer_result.ValueOrDie().get(),
                                             *handle_result.ValueOrDie());
  if (!status.ok()) {
    response->set_err(status.error_message());
    return ::grpc::Status::OK;
  }
  response->set_keyset(keyset.str());
  return ::grpc::Status::OK;
}

}  // namespace tink_testing_api
