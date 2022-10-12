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

// Implementation of a PrfSet Service.
#include "prf_set_impl.h"

#include <memory>
#include <string>
#include <utility>

#include "tink/prf/prf_set.h"
#include "create.h"
#include "proto/testing_api.grpc.pb.h"

namespace tink_testing_api {

using ::crypto::tink::util::StatusOr;
using ::grpc::ServerContext;
using ::grpc::Status;

::grpc::Status PrfSetImpl::Create(grpc::ServerContext* context,
                                  const CreationRequest* request,
                                  CreationResponse* response) {
  return CreatePrimitiveForRpc<crypto::tink::PrfSet>(request, response);
}

// Returns the Key Ids of the Keyset.
::grpc::Status PrfSetImpl::KeyIds(ServerContext* context,
                                  const PrfSetKeyIdsRequest* request,
                                  PrfSetKeyIdsResponse* response) {
  StatusOr<std::unique_ptr<crypto::tink::PrfSet>> prf_set_result =
      PrimitiveFromSerializedBinaryProtoKeyset<crypto::tink::PrfSet>(
          request->annotated_keyset());
  if (!prf_set_result.ok()) {
    response->set_err(std::string(prf_set_result.status().message()));
    return ::grpc::Status::OK;
  }
  auto* output = response->mutable_output();
  output->set_primary_key_id(prf_set_result.value()->GetPrimaryId());
  for (auto const& item : prf_set_result.value()->GetPrfs()) {
    output->add_key_id(item.first);
  }
  return ::grpc::Status::OK;
}

// Computes the output of one PRF.
::grpc::Status PrfSetImpl::Compute(ServerContext* context,
                                   const PrfSetComputeRequest* request,
                                   PrfSetComputeResponse* response) {
  StatusOr<std::unique_ptr<crypto::tink::PrfSet>> prf_set_result =
      PrimitiveFromSerializedBinaryProtoKeyset<crypto::tink::PrfSet>(
          request->annotated_keyset());
  if (!prf_set_result.ok()) {
    response->set_err(std::string(prf_set_result.status().message()));
    return ::grpc::Status::OK;
  }
  auto prfs = prf_set_result.value()->GetPrfs();
  auto prf_it = prfs.find(request->key_id());
  if (prf_it == prfs.end()) {
    response->set_err("Unknown key ID.");
    return ::grpc::Status::OK;
  }
  auto compute_result =
      prf_it->second->Compute(request->input_data(), request->output_length());
  if (!compute_result.ok()) {
    response->set_err(std::string(compute_result.status().message()));
    return ::grpc::Status::OK;
  }
  response->set_output(compute_result.value());
  return ::grpc::Status::OK;
}

}  // namespace tink_testing_api
