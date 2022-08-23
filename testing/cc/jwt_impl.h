// Copyright 2021 Google LLC
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

#ifndef TINK_TESTING_JWT_IMPL_H_
#define TINK_TESTING_JWT_IMPL_H_

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/status.h>

#include "proto/testing_api.grpc.pb.h"

namespace tink_testing_api {

// A Jwt Service.
class JwtImpl final : public Jwt::Service {
 public:
  grpc::Status CreateJwtMac(grpc::ServerContext* context,
                            const CreationRequest* request,
                            CreationResponse* response) override;

  grpc::Status CreateJwtPublicKeySign(grpc::ServerContext* context,
                                      const CreationRequest* request,
                                      CreationResponse* response) override;

  grpc::Status CreateJwtPublicKeyVerify(grpc::ServerContext* context,
                                        const CreationRequest* request,
                                        CreationResponse* response) override;

  grpc::Status ComputeMacAndEncode(grpc::ServerContext* context,
                                   const JwtSignRequest* request,
                                   JwtSignResponse* response) override;

  grpc::Status VerifyMacAndDecode(grpc::ServerContext* context,
                                  const JwtVerifyRequest* request,
                                  JwtVerifyResponse* response) override;

  grpc::Status PublicKeySignAndEncode(grpc::ServerContext* context,
                                   const JwtSignRequest* request,
                                   JwtSignResponse* response) override;

  grpc::Status PublicKeyVerifyAndDecode(grpc::ServerContext* context,
                                  const JwtVerifyRequest* request,
                                  JwtVerifyResponse* response) override;

  grpc::Status ToJwkSet(grpc::ServerContext* context,
                        const JwtToJwkSetRequest* request,
                        JwtToJwkSetResponse* response) override;

  grpc::Status FromJwkSet(grpc::ServerContext* context,
                          const JwtFromJwkSetRequest* request,
                          JwtFromJwkSetResponse* response) override;
};

}  // namespace tink_testing_api

#endif  // TINK_TESTING_JWT_IMPL_H_
