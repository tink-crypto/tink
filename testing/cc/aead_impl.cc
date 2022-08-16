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

// Implementation of an AEAD Service.
#include "aead_impl.h"

#include <string>
#include <utility>

#include "tink/aead.h"
#include "tink/binary_keyset_reader.h"
#include "tink/cleartext_keyset_handle.h"

namespace tink_testing_api {

using ::crypto::tink::BinaryKeysetReader;
using ::crypto::tink::CleartextKeysetHandle;

::grpc::Status AeadImpl::CreateAead(grpc::ServerContext* context,
                                    const AeadCreationRequest* request,
                                    AeadCreationResponse* response) {
  auto reader_result = BinaryKeysetReader::New(request->keyset());
  if (!reader_result.ok()) {
    response->set_err(std::string(reader_result.status().message()));
    return ::grpc::Status::OK;
  }
  auto handle_result =
      CleartextKeysetHandle::Read(std::move(reader_result.value()));
  if (!handle_result.ok()) {
    response->set_err(std::string(handle_result.status().message()));
    return ::grpc::Status::OK;
  }
  auto aead_result = handle_result.value()->GetPrimitive<crypto::tink::Aead>();
  if (!aead_result.ok()) {
    response->set_err(std::string(aead_result.status().message()));
    return ::grpc::Status::OK;
  }
  return ::grpc::Status::OK;
}

::grpc::Status AeadImpl::Encrypt(grpc::ServerContext* context,
                                 const AeadEncryptRequest* request,
                                 AeadEncryptResponse* response) {
  auto reader_result = BinaryKeysetReader::New(request->keyset());
  if (!reader_result.ok()) {
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION,
                          "Reading Keyset failed");
  }
  auto handle_result =
      CleartextKeysetHandle::Read(std::move(reader_result.value()));
  if (!handle_result.ok()) {
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION,
                          "Creating KeysetHandle failed");
  }
  auto aead_result = handle_result.value()->GetPrimitive<crypto::tink::Aead>();
  if (!aead_result.ok()) {
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION,
                          "Creating Aead failed");
  }
  auto encrypt_result = aead_result.value()->Encrypt(
      request->plaintext(), request->associated_data());
  if (!encrypt_result.ok()) {
    response->set_err(std::string(encrypt_result.status().message()));
    return ::grpc::Status::OK;
  }
  response->set_ciphertext(encrypt_result.value());
  return ::grpc::Status::OK;
}

::grpc::Status AeadImpl::Decrypt(grpc::ServerContext* context,
                                 const AeadDecryptRequest* request,
                                 AeadDecryptResponse* response) {
  auto reader_result = BinaryKeysetReader::New(request->keyset());
  if (!reader_result.ok()) {
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION,
                          "Reading Keyset failed");
  }
  auto handle_result =
      CleartextKeysetHandle::Read(std::move(reader_result.value()));
  if (!handle_result.ok()) {
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION,
                          "Creating KeysetHandle failed");
  }
  auto aead_result = handle_result.value()->GetPrimitive<crypto::tink::Aead>();
  if (!aead_result.ok()) {
    return ::grpc::Status(::grpc::StatusCode::FAILED_PRECONDITION,
                          "Creating Aead failed");
  }
  auto decrypt_result = aead_result.value()->Decrypt(
      request->ciphertext(), request->associated_data());
  if (!decrypt_result.ok()) {
    response->set_err(std::string(decrypt_result.status().message()));
    return ::grpc::Status::OK;
  }
  response->set_plaintext(decrypt_result.value());
  return ::grpc::Status::OK;
}

}  // namespace tink_testing_api
