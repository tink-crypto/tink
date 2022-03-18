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

// Implementation of a Hybrid encryption service
#include "hybrid_impl.h"

#include <string>
#include <utility>

#include "tink/binary_keyset_reader.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "proto/testing/testing_api.grpc.pb.h"

namespace tink_testing_api {

using ::crypto::tink::BinaryKeysetReader;
using ::crypto::tink::CleartextKeysetHandle;
using ::grpc::ServerContext;
using ::grpc::Status;

// Encrypts a message
::grpc::Status HybridImpl::Encrypt(grpc::ServerContext* context,
                                   const HybridEncryptRequest* request,
                                   HybridEncryptResponse* response) {
  auto reader_result = BinaryKeysetReader::New(request->public_keyset());
  if (!reader_result.ok()) {
    response->set_err(std::string(reader_result.status().message()));
    return ::grpc::Status::OK;
  }
  auto public_handle_result =
      CleartextKeysetHandle::Read(std::move(reader_result.value()));
  if (!public_handle_result.ok()) {
    response->set_err(std::string(public_handle_result.status().message()));
    return ::grpc::Status::OK;
  }
  auto hybrid_encrypt_result =
      public_handle_result.value()->GetPrimitive<crypto::tink::HybridEncrypt>();
  if (!hybrid_encrypt_result.ok()) {
    response->set_err(std::string(hybrid_encrypt_result.status().message()));
    return ::grpc::Status::OK;
  }
  auto enc_result = hybrid_encrypt_result.value()->Encrypt(
      request->plaintext(), request->context_info());
  if (!enc_result.ok()) {
    response->set_err(std::string(enc_result.status().message()));
    return ::grpc::Status::OK;
  }
  response->set_ciphertext(enc_result.value());
  return ::grpc::Status::OK;
}

// Decrypts a ciphertext
::grpc::Status HybridImpl::Decrypt(grpc::ServerContext* context,
                                   const HybridDecryptRequest* request,
                                   HybridDecryptResponse* response) {
  auto reader_result = BinaryKeysetReader::New(request->private_keyset());
  if (!reader_result.ok()) {
    response->set_err(std::string(reader_result.status().message()));
    return ::grpc::Status::OK;
  }
  auto private_handle_result =
      CleartextKeysetHandle::Read(std::move(reader_result.value()));
  if (!private_handle_result.ok()) {
    response->set_err(std::string(private_handle_result.status().message()));
    return ::grpc::Status::OK;
  }
  auto hybrid_decrypt_result =
      private_handle_result.value()
          ->GetPrimitive<crypto::tink::HybridDecrypt>();
  if (!hybrid_decrypt_result.ok()) {
    response->set_err(std::string(hybrid_decrypt_result.status().message()));
    return ::grpc::Status::OK;
  }
  auto dec_result = hybrid_decrypt_result.value()->Decrypt(
      request->ciphertext(), request->context_info());
  if (!dec_result.ok()) {
    response->set_err(std::string(dec_result.status().message()));
    return ::grpc::Status::OK;
  }
  response->set_plaintext(dec_result.value());
  return ::grpc::Status::OK;
}

}  // namespace tink_testing_api
