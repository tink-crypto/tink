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

#include "tink/binary_keyset_reader.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/prf/prf_set.h"
#include "proto/testing/testing_api.grpc.pb.h"

namespace tink_testing_api {

using ::crypto::tink::BinaryKeysetReader;
using ::crypto::tink::CleartextKeysetHandle;
using ::grpc::ServerContext;
using ::grpc::Status;

// Returns the Key Ids of the Keyset.
::grpc::Status PrfSetImpl::KeyIds(ServerContext* context,
                                  const PrfSetKeyIdsRequest* request,
                                  PrfSetKeyIdsResponse* response) {
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
  auto prf_set_result =
      handle_result.ValueOrDie()->GetPrimitive<crypto::tink::PrfSet>();
  if (!prf_set_result.ok()) {
    response->set_err(prf_set_result.status().error_message());
    return ::grpc::Status::OK;
  }
  auto* output = response->mutable_output();
  output->set_primary_key_id(prf_set_result.ValueOrDie()->GetPrimaryId());
  for (auto const& item : prf_set_result.ValueOrDie()->GetPrfs()) {
    output->add_key_id(item.first);
  }
  return ::grpc::Status::OK;
}

// Computes the output of one PRF.
::grpc::Status PrfSetImpl::Compute(ServerContext* context,
                                   const PrfSetComputeRequest* request,
                                   PrfSetComputeResponse* response) {
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
  auto prf_set_result =
      handle_result.ValueOrDie()->GetPrimitive<crypto::tink::PrfSet>();
  if (!prf_set_result.ok()) {
    response->set_err(prf_set_result.status().error_message());
    return ::grpc::Status::OK;
  }
  auto prfs = prf_set_result.ValueOrDie()->GetPrfs();
  auto prf_it = prfs.find(request->key_id());
  if (prf_it == prfs.end()) {
    response->set_err("Unknown key ID.");
    return ::grpc::Status::OK;
  }
  auto compute_result =
      prf_it->second->Compute(request->input_data(), request->output_length());
  if (!compute_result.ok()) {
    response->set_err(compute_result.status().error_message());
    return ::grpc::Status::OK;
  }
  response->set_output(compute_result.ValueOrDie());
  return ::grpc::Status::OK;
}

}  // namespace tink_testing_api
