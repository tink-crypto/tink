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

#include <grpcpp/grpcpp.h>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "tink/config/tink_config.h"
#include "tink/jwt/jwt_mac_config.h"
#include "tink/jwt/jwt_signature_config.h"
#include "tink/util/fake_kms_client.h"
#include "proto/testing/testing_api.grpc.pb.h"
#include "aead_impl.h"
#include "deterministic_aead_impl.h"
#include "hybrid_impl.h"
#include "keyset_impl.h"
#include "mac_impl.h"
#include "metadata_impl.h"
#include "prf_set_impl.h"
#include "signature_impl.h"
#include "streaming_aead_impl.h"
#include "jwt_impl.h"

ABSL_FLAG(int, port, 23456, "the port");

void RunServer() {
  auto status = crypto::tink::TinkConfig::Register();
  if (!status.ok()) {
    std::cout << "TinkConfig::Register() failed: " << status.message()
              << std::endl;
    return;
  }
  auto jwt_mac_status = crypto::tink::JwtMacRegister();
  if (!jwt_mac_status.ok()) {
    std::cout << "JwtMacRegister() failed: " << jwt_mac_status.message()
              << std::endl;
    return;
  }
  auto jwt_signature_status = crypto::tink::JwtSignatureRegister();
  if (!jwt_signature_status.ok()) {
    std::cout << "JwtSignatureRegister() failed: "
              << jwt_signature_status.message() << std::endl;
    return;
  }
  auto register_fake_kms_client_status =
      crypto::tink::test::FakeKmsClient::RegisterNewClient("", "");
  if (!register_fake_kms_client_status.ok()) {
    std::cout << "FakeKmsClient::RegisterNewClient("
                 ", "
                 ") failed: "
              << register_fake_kms_client_status.message() << std::endl;
    return;
  }

  const int port = absl::GetFlag(FLAGS_port);
  std::string server_address = absl::StrCat("[::]:", port);

  tink_testing_api::MetadataImpl metadata;
  tink_testing_api::KeysetImpl keyset;
  tink_testing_api::AeadImpl aead;
  tink_testing_api::DeterministicAeadImpl deterministic_aead;
  tink_testing_api::HybridImpl hybrid;
  tink_testing_api::MacImpl mac;
  tink_testing_api::SignatureImpl signature;
  tink_testing_api::StreamingAeadImpl streaming_aead;
  tink_testing_api::PrfSetImpl prf_set;
  tink_testing_api::JwtImpl jwt;

  grpc::ServerBuilder builder;
  builder.AddListeningPort(
      server_address, ::grpc::experimental::LocalServerCredentials(LOCAL_TCP));

  builder.RegisterService(&metadata);
  builder.RegisterService(&keyset);
  builder.RegisterService(&aead);
  builder.RegisterService(&deterministic_aead);
  builder.RegisterService(&hybrid);
  builder.RegisterService(&mac);
  builder.RegisterService(&signature);
  builder.RegisterService(&prf_set);
  builder.RegisterService(&streaming_aead);
  builder.RegisterService(&jwt);

  std::unique_ptr<grpc::Server> server(builder.BuildAndStart());
  std::cout << "Server listening on " << server_address << std::endl;
  server->Wait();
}

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);
  RunServer();
  return 0;
}
