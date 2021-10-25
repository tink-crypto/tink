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

#include "tink/binary_keyset_reader.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/mac.h"
#include "proto/testing/testing_api.grpc.pb.h"

namespace tink_testing_api {

using ::crypto::tink::BinaryKeysetReader;
using ::crypto::tink::CleartextKeysetHandle;
using ::grpc::ServerContext;
using ::grpc::Status;

// Computes a MAC
::grpc::Status MacImpl::ComputeMac(grpc::ServerContext* context,
                                   const ComputeMacRequest* request,
                                   ComputeMacResponse* response) {
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
  auto mac_result =
      handle_result.ValueOrDie()->GetPrimitive<crypto::tink::Mac>();
  if (!mac_result.ok()) {
    response->set_err(std::string(mac_result.status().message()));
    return ::grpc::Status::OK;
  }
  auto compute_result = mac_result.ValueOrDie()->ComputeMac(request->data());
  if (!compute_result.ok()) {
    response->set_err(std::string(compute_result.status().message()));
    return ::grpc::Status::OK;
  }
  response->set_mac_value(compute_result.ValueOrDie());
  return ::grpc::Status::OK;
}

// Verifies a MAC
::grpc::Status MacImpl::VerifyMac(grpc::ServerContext* context,
                                  const VerifyMacRequest* request,
                                  VerifyMacResponse* response) {
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
  auto mac_result =
      handle_result.ValueOrDie()->GetPrimitive<crypto::tink::Mac>();
  if (!mac_result.ok()) {
    response->set_err(std::string(mac_result.status().message()));
    return ::grpc::Status::OK;
  }
  auto status =
      mac_result.ValueOrDie()->VerifyMac(request->mac_value(), request->data());
  if (!status.ok()) {
    response->set_err(std::string(status.message()));
    return ::grpc::Status::OK;
  }
  return ::grpc::Status::OK;
}

}  // namespace tink_testing_api
