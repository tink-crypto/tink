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

// Implementation of an Deterministic AEAD Service.
#include "deterministic_aead_impl.h"

#include <memory>
#include <string>
#include <utility>

#include "tink/binary_keyset_reader.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/deterministic_aead.h"
#include "create.h"
#include "proto/testing_api.grpc.pb.h"

namespace tink_testing_api {

using ::crypto::tink::util::StatusOr;

grpc::Status DeterministicAeadImpl::Create(grpc::ServerContext* context,
                                           const CreationRequest* request,
                                           CreationResponse* response) {
  return CreatePrimitiveForRpc<crypto::tink::DeterministicAead>(request,
                                                                response);
}

grpc::Status DeterministicAeadImpl::EncryptDeterministically(
    grpc::ServerContext* context,
    const DeterministicAeadEncryptRequest* request,
    DeterministicAeadEncryptResponse* response) {
  StatusOr<std::unique_ptr<crypto::tink::DeterministicAead>> daead =
      PrimitiveFromSerializedBinaryProtoKeyset<crypto::tink::DeterministicAead>(
          request->keyset());
  if (!daead.ok()) {
    return grpc::Status(
        grpc::StatusCode::FAILED_PRECONDITION,
        absl::StrCat("Creating primitive failed: ", daead.status().message()));
  }

  StatusOr<std::string> ciphertext = (*daead)->EncryptDeterministically(
      request->plaintext(), request->associated_data());
  if (!ciphertext.ok()) {
    response->set_err(std::string(ciphertext.status().message()));
    return grpc::Status::OK;
  }
  response->set_ciphertext(*ciphertext);
  return grpc::Status::OK;
}

grpc::Status DeterministicAeadImpl::DecryptDeterministically(
    grpc::ServerContext* context,
    const DeterministicAeadDecryptRequest* request,
    DeterministicAeadDecryptResponse* response) {
  StatusOr<std::unique_ptr<crypto::tink::DeterministicAead>> daead =
      PrimitiveFromSerializedBinaryProtoKeyset<crypto::tink::DeterministicAead>(
          request->keyset());
  if (!daead.ok()) {
    return grpc::Status(
        grpc::StatusCode::FAILED_PRECONDITION,
        absl::StrCat("Creating primitive failed: ", daead.status().message()));
  }
  StatusOr<std::string> plaintext = (*daead)->DecryptDeterministically(
      request->ciphertext(), request->associated_data());
  if (!plaintext.ok()) {
    response->set_err(std::string(plaintext.status().message()));
    return grpc::Status::OK;
  }
  response->set_plaintext(*plaintext);
  return grpc::Status::OK;
}

}  // namespace tink_testing_api
