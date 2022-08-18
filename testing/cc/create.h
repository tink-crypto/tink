// Copyright 2022 Google LLC
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

#ifndef TINK_TESTING_CREATE_H_
#define TINK_TESTING_CREATE_H_

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/status.h>

#include <memory>
#include <string>
#include <utility>

#include "tink/binary_keyset_reader.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_reader.h"
#include "proto/testing_api.grpc.pb.h"

namespace tink_testing_api {

// Tries to create a primitive from a keyset serialized in binary proto format.
// This function might be better in Tink itself (except that it should take an
// optional SecretKeyAccessToken).
template <typename T>
crypto::tink::util::StatusOr<std::unique_ptr<T>>
PrimitiveFromSerializedBinaryProtoKeyset(absl::string_view keyset) {
  crypto::tink::util::StatusOr<std::unique_ptr<crypto::tink::KeysetReader>>
      reader = crypto::tink::BinaryKeysetReader::New(keyset);
  if (!reader.ok()) {
    return reader.status();
  }
  crypto::tink::util::StatusOr<std::unique_ptr<crypto::tink::KeysetHandle>>
      handle = crypto::tink::CleartextKeysetHandle::Read(*std::move(reader));
  if (!handle.ok()) {
    return handle.status();
  }
  return (*handle)->GetPrimitive<T>();
}

// Tries to create a primitive of type T from the creation request and
// populates the response accordingly. This can be used in implementations
// of the "Create" RPC calls in the Tink Services.
template <typename T>
grpc::Status CreatePrimitiveForRpc(const CreationRequest* request,
                                   CreationResponse* response) {
  crypto::tink::util::StatusOr<std::unique_ptr<T>> primitive =
      PrimitiveFromSerializedBinaryProtoKeyset<T>(request->keyset());
  if (!primitive.ok()) {
    response->set_err(std::string(primitive.status().message()));
  }
  return grpc::Status::OK;
}

}  // namespace tink_testing_api

#endif  // TINK_TESTING_CREATE_H_
