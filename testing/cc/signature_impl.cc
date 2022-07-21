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

#include <string>
#include <utility>

#include "tink/binary_keyset_reader.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/public_key_sign.h"
#include "tink/public_key_verify.h"
#include "proto/testing_api.grpc.pb.h"

namespace tink_testing_api {

using ::crypto::tink::BinaryKeysetReader;
using ::crypto::tink::CleartextKeysetHandle;
using ::grpc::ServerContext;
using ::grpc::Status;

// Signs a message
::grpc::Status SignatureImpl::Sign(grpc::ServerContext* context,
                                   const SignatureSignRequest* request,
                                   SignatureSignResponse* response) {
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
  auto signer_result = private_handle_result.value()
                           ->GetPrimitive<crypto::tink::PublicKeySign>();
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
  auto verifier_result = public_handle_result.value()
                             ->GetPrimitive<crypto::tink::PublicKeyVerify>();
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
