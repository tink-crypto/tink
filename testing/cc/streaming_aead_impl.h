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

#ifndef TINK_TESTING_SERIVCES_STREAMING_AEAD_IMPL_H_
#define TINK_TESTING_SERIVCES_STREAMING_AEAD_IMPL_H_

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/status.h>

#include "proto/testing_api.grpc.pb.h"

namespace tink_testing_api {

// A StreamingAead Service.
class StreamingAeadImpl final : public StreamingAead::Service {
 public:
  grpc::Status Encrypt(grpc::ServerContext* context,
                       const StreamingAeadEncryptRequest* request,
                       StreamingAeadEncryptResponse* response) override;

  grpc::Status Decrypt(grpc::ServerContext* context,
                       const StreamingAeadDecryptRequest* request,
                       StreamingAeadDecryptResponse* response) override;
};

}  // namespace tink_testing_api

#endif  // TINK_TESTING_SERIVCES_STREAMING_AEAD_IMPL_H_
