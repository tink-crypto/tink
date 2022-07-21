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

#ifndef TINK_TESTING_SERIVCES_KEYSET_IMPL_H_
#define TINK_TESTING_SERIVCES_KEYSET_IMPL_H_

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include <grpcpp/support/status.h>

#include <string>

#include "absl/container/flat_hash_map.h"
#include "proto/tink.pb.h"
#include "proto/testing_api.grpc.pb.h"

namespace tink_testing_api {

// A Keyset Service.
class KeysetImpl final : public Keyset::Service {
 public:
  // Returns the key template for the given template name.
  grpc::Status GetTemplate(grpc::ServerContext* context,
                           const KeysetTemplateRequest* request,
                           KeysetTemplateResponse* response) override;

  // Generates a new keyset with one key from a template.
  grpc::Status Generate(grpc::ServerContext* context,
                        const KeysetGenerateRequest* request,
                        KeysetGenerateResponse* response) override;

  // Returns a public keyset for a given private keyset.
  grpc::Status Public(grpc::ServerContext* context,
                      const KeysetPublicRequest* request,
                      KeysetPublicResponse* response) override;

  // Converts a keyset from binary to JSON format.
  grpc::Status ToJson(grpc::ServerContext* context,
                      const KeysetToJsonRequest* request,
                      KeysetToJsonResponse* response) override;

  // Converts a keyset from JSON to binary format.
  grpc::Status FromJson(grpc::ServerContext* context,
                        const KeysetFromJsonRequest* request,
                        KeysetFromJsonResponse* response) override;

  // Writes an encrypted keyset.
  grpc::Status WriteEncrypted(grpc::ServerContext* context,
                              const KeysetWriteEncryptedRequest* request,
                              KeysetWriteEncryptedResponse* response) override;

  // Reads an encrypted keyset.
  grpc::Status ReadEncrypted(grpc::ServerContext* context,
                             const KeysetReadEncryptedRequest* request,
                             KeysetReadEncryptedResponse* response) override;
  KeysetImpl();

 private:
  absl::flat_hash_map<std::string, google::crypto::tink::KeyTemplate>
      key_templates_;
};

}  // namespace tink_testing_api

#endif  // TINK_TESTING_SERIVCES_KEYSET_IMPL_H_
