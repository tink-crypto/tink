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

// Implementation of a Signature Service
#include "signature_impl.h"

#include <memory>
#include <string>
#include <utility>

#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "create.h"
#include "proto/testing_api.grpc.pb.h"

namespace tink_testing_api {

using ::crypto::tink::util::StatusOr;

::grpc::Status SignatureImpl::CreatePublicKeySign(
    grpc::ServerContext* context, const CreationRequest* request,
    CreationResponse* response) {
  return CreatePrimitiveForRpc<crypto::tink::PublicKeySign>(request, response);
}

::grpc::Status SignatureImpl::CreatePublicKeyVerify(
    grpc::ServerContext* context, const CreationRequest* request,
    CreationResponse* response) {
  return CreatePrimitiveForRpc<crypto::tink::PublicKeyVerify>(request,
                                                              response);
}

// Signs a message
::grpc::Status SignatureImpl::Sign(grpc::ServerContext* context,
                                   const SignatureSignRequest* request,
                                   SignatureSignResponse* response) {
  StatusOr<std::unique_ptr<crypto::tink::PublicKeySign>> signer_result =
      PrimitiveFromSerializedBinaryProtoKeyset<crypto::tink::PublicKeySign>(
          request->private_annotated_keyset());
  if (!signer_result.ok()) {
    response->set_err(std::string(signer_result.status().message()));
    return ::grpc::Status::OK;
  }
  auto sign_result = signer_result.value()->Sign(request->data());
  if (!sign_result.ok()) {
    response->set_err(std::string(sign_result.status().message()));
    return ::grpc::Status::OK;
  }
  response->set_signature(sign_result.value());
  return ::grpc::Status::OK;
}

// Verifies a signature
::grpc::Status SignatureImpl::Verify(grpc::ServerContext* context,
                                     const SignatureVerifyRequest* request,
                                     SignatureVerifyResponse* response) {
  StatusOr<std::unique_ptr<crypto::tink::PublicKeyVerify>> verifier_result =
      PrimitiveFromSerializedBinaryProtoKeyset<crypto::tink::PublicKeyVerify>(
          request->public_annotated_keyset());
  if (!verifier_result.ok()) {
    response->set_err(std::string(verifier_result.status().message()));
    return ::grpc::Status::OK;
  }
  auto status =
      verifier_result.value()->Verify(request->signature(), request->data());
  if (!status.ok()) {
    response->set_err(std::string(status.message()));
    return ::grpc::Status::OK;
  }
  return ::grpc::Status::OK;
}

}  // namespace tink_testing_api
