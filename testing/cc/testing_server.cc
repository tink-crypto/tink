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

#include <iostream>
#include <memory>
#include <ostream>
#include <string>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/str_cat.h"
#include "tink/config/tink_config.h"
#include "tink/hybrid/hpke_config.h"
#ifdef TINK_CROSS_LANG_TESTS_AWSKMS
#include "tink/integration/awskms/aws_kms_client.h"
#endif  // TINK_CROSS_LANG_TESTS_AWSKMS
#include "tink/integration/gcpkms/gcp_kms_client.h"
#include "tink/jwt/jwt_mac_config.h"
#include "tink/jwt/jwt_signature_config.h"
#include "tink/util/fake_kms_client.h"
#include "tink/util/status.h"
#include "aead_impl.h"
#include "deterministic_aead_impl.h"
#include "hybrid_impl.h"
#include "jwt_impl.h"
#include "keyset_impl.h"
#include "mac_impl.h"
#include "metadata_impl.h"
#include "prf_set_impl.h"
#include "signature_impl.h"
#include "streaming_aead_impl.h"
#include "proto/testing_api.grpc.pb.h"

ABSL_FLAG(int, port, 23456, "the port");
ABSL_FLAG(std::string, gcp_credentials_path, "",
          "Google Cloud KMS credentials path");
ABSL_FLAG(
    std::string, gcp_key_uri, "",
    absl::StrCat("Google Cloud KMS key URL of the form: ",
                 "gcp-kms://projects/*/locations/*/keyRings/*/cryptoKeys/*."));
ABSL_FLAG(std::string, aws_credentials_path, "", "AWS KMS credentials path");
ABSL_FLAG(
    std::string, aws_key_uri, "",
    absl::StrCat("AWS KMS key URL of the form: ",
                 "aws-kms://arn:aws:kms:<region>:<account-id>:key/<key-id>."));

namespace tink_testing_api {

void RunServer() {
  auto status = crypto::tink::TinkConfig::Register();
  if (!status.ok()) {
    std::cerr << "TinkConfig::Register() failed: " << status.message()
              << std::endl;
    return;
  }
  auto hpke_status = crypto::tink::RegisterHpke();
  if (!hpke_status.ok()) {
    std::cerr << "RegisterHpke() failed: " << hpke_status.message()
              << std::endl;
    return;
  }
  auto jwt_mac_status = crypto::tink::JwtMacRegister();
  if (!jwt_mac_status.ok()) {
    std::cerr << "JwtMacRegister() failed: " << jwt_mac_status.message()
              << std::endl;
    return;
  }
  auto jwt_signature_status = crypto::tink::JwtSignatureRegister();
  if (!jwt_signature_status.ok()) {
    std::cerr << "JwtSignatureRegister() failed: "
              << jwt_signature_status.message() << std::endl;
    return;
  }
  auto register_fake_kms_client_status =
      crypto::tink::test::FakeKmsClient::RegisterNewClient("", "");
  if (!register_fake_kms_client_status.ok()) {
    std::cerr << "FakeKmsClient::RegisterNewClient(\"\", \"\") failed: "
              << register_fake_kms_client_status.message() << std::endl;
    return;
  }
  std::string gcp_credentials_path = absl::GetFlag(FLAGS_gcp_credentials_path);
  std::string gcp_key_uri = absl::GetFlag(FLAGS_gcp_key_uri);
  crypto::tink::util::Status register_gcpkms_client_status =
      crypto::tink::integration::gcpkms::GcpKmsClient::RegisterNewClient(
          gcp_key_uri, gcp_credentials_path);
  if (!register_gcpkms_client_status.ok()) {
    std::cerr << "GcpKmsClient::RegisterNewClient(\"\", \""
              << gcp_credentials_path
              << "\") failed: " << register_gcpkms_client_status.message()
              << std::endl;
    return;
  }
#ifdef TINK_CROSS_LANG_TESTS_AWSKMS
  std::string aws_credentials_path = absl::GetFlag(FLAGS_aws_credentials_path);
  std::string aws_key_uri = absl::GetFlag(FLAGS_aws_key_uri);
  crypto::tink::util::Status register_awskms_client_status =
      crypto::tink::integration::awskms::AwsKmsClient::RegisterNewClient(
          aws_key_uri, aws_credentials_path);
  if (!register_awskms_client_status.ok()) {
    std::cerr << "AwsKmsClient::RegisterNewClient(\"\", \""
              << aws_credentials_path
              << "\") failed: " << register_awskms_client_status.message()
              << std::endl;
    return;
  }
#endif  // TINK_CROSS_LANG_TESTS_AWSKMS

  const int port = absl::GetFlag(FLAGS_port);
  std::string server_address = absl::StrCat("[::]:", port);

  MetadataImpl metadata;
  KeysetImpl keyset;
  AeadImpl aead;
  DeterministicAeadImpl deterministic_aead;
  HybridImpl hybrid;
  MacImpl mac;
  SignatureImpl signature;
  StreamingAeadImpl streaming_aead;
  PrfSetImpl prf_set;
  JwtImpl jwt;

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

}  // namespace tink_testing_api

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);
  tink_testing_api::RunServer();
  return 0;
}
