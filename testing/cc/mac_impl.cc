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

// Implementation of a MAC Service.
#include "mac_impl.h"

#include <memory>
#include <string>
#include <utility>

#include "tink/mac.h"
#include "create.h"
#include "proto/testing_api.grpc.pb.h"

namespace tink_testing_api {

using ::crypto::tink::util::StatusOr;
using ::grpc::ServerContext;
using ::grpc::Status;

::grpc::Status MacImpl::Create(grpc::ServerContext* context,
                               const CreationRequest* request,
                               CreationResponse* response) {
  return CreatePrimitiveForRpc<crypto::tink::Mac>(request, response);
}

// Computes a MAC
::grpc::Status MacImpl::ComputeMac(grpc::ServerContext* context,
                                   const ComputeMacRequest* request,
                                   ComputeMacResponse* response) {
  StatusOr<std::unique_ptr<crypto::tink::Mac>> mac_result =
      PrimitiveFromSerializedBinaryProtoKeyset<crypto::tink::Mac>(
          request->annotated_keyset());
  if (!mac_result.ok()) {
    response->set_err(std::string(mac_result.status().message()));
    return ::grpc::Status::OK;
  }
  auto compute_result = mac_result.value()->ComputeMac(request->data());
  if (!compute_result.ok()) {
    response->set_err(std::string(compute_result.status().message()));
    return ::grpc::Status::OK;
  }
  response->set_mac_value(compute_result.value());
  return ::grpc::Status::OK;
}

// Verifies a MAC
::grpc::Status MacImpl::VerifyMac(grpc::ServerContext* context,
                                  const VerifyMacRequest* request,
                                  VerifyMacResponse* response) {
  StatusOr<std::unique_ptr<crypto::tink::Mac>> mac_result =
      PrimitiveFromSerializedBinaryProtoKeyset<crypto::tink::Mac>(
          request->annotated_keyset());
  if (!mac_result.ok()) {
    response->set_err(std::string(mac_result.status().message()));
    return ::grpc::Status::OK;
  }
  auto status =
      mac_result.value()->VerifyMac(request->mac_value(), request->data());
  if (!status.ok()) {
    response->set_err(std::string(status.message()));
    return ::grpc::Status::OK;
  }
  return ::grpc::Status::OK;
}

}  // namespace tink_testing_api
