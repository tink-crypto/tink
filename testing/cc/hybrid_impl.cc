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

#include <memory>
#include <string>
#include <utility>

#include "tink/hybrid_decrypt.h"
#include "tink/hybrid_encrypt.h"
#include "tink/util/statusor.h"
#include "create.h"
#include "proto/testing_api.grpc.pb.h"

namespace tink_testing_api {

using ::crypto::tink::util::StatusOr;
using ::grpc::ServerContext;
using ::grpc::Status;

::grpc::Status HybridImpl::CreateHybridEncrypt(grpc::ServerContext* context,
                                               const CreationRequest* request,
                                               CreationResponse* response) {
  return CreatePrimitiveForRpc<crypto::tink::HybridEncrypt>(request, response);
}

::grpc::Status HybridImpl::CreateHybridDecrypt(grpc::ServerContext* context,
                                               const CreationRequest* request,
                                               CreationResponse* response) {
  return CreatePrimitiveForRpc<crypto::tink::HybridDecrypt>(request, response);
}

::grpc::Status HybridImpl::Encrypt(grpc::ServerContext* context,
                                   const HybridEncryptRequest* request,
                                   HybridEncryptResponse* response) {
  StatusOr<std::unique_ptr<crypto::tink::HybridEncrypt>> hybrid_encrypt_result =
      PrimitiveFromSerializedBinaryProtoKeyset<crypto::tink::HybridEncrypt>(
          request->public_annotated_keyset());
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
  StatusOr<std::unique_ptr<crypto::tink::HybridDecrypt>> hybrid_decrypt_result =
      PrimitiveFromSerializedBinaryProtoKeyset<crypto::tink::HybridDecrypt>(
          request->private_annotated_keyset());
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
