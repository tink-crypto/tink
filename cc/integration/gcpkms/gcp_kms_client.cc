// Copyright 2019 Google LLC
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
#include "tink/integration/gcpkms/gcp_kms_client.h"

#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <utility>

#include "grpcpp/channel.h"
#include "grpcpp/create_channel.h"
#include "grpcpp/security/credentials.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/integration/gcpkms/gcp_kms_aead.h"
#include "tink/kms_clients.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/version.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {

namespace {

using ::google::cloud::kms::v1::KeyManagementService;

static constexpr absl::string_view kKeyUriPrefix = "gcp-kms://";
static constexpr absl::string_view kGcpKmsServer = "cloudkms.googleapis.com";
static constexpr absl::string_view kTinkUserAgentPrefix = "Tink/";

util::StatusOr<std::string> ReadFile(absl::string_view filename) {
  std::ifstream input_stream;
  input_stream.open(std::string(filename), std::ifstream::in);
  if (!input_stream.is_open()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("Error reading file ", filename));
  }
  std::stringstream input;
  input << input_stream.rdbuf();
  input_stream.close();
  return input.str();
}

util::StatusOr<std::shared_ptr<grpc::ChannelCredentials>> GetCredentials(
    absl::string_view credentials_path) {
  if (credentials_path.empty()) {
    std::shared_ptr<grpc::ChannelCredentials> creds =
        grpc::GoogleDefaultCredentials();
    if (creds == nullptr) {
      return util::Status(absl::StatusCode::kInternal,
                          "Could not read default credentials");
    }
    return creds;
  }

  // Try reading credentials from a file.
  util::StatusOr<std::string> json_creds_result = ReadFile(credentials_path);
  if (!json_creds_result.ok()) {
    return json_creds_result.status();
  }
  std::shared_ptr<grpc::CallCredentials> creds =
      grpc::ServiceAccountJWTAccessCredentials(json_creds_result.value());
  if (creds == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("Could not load credentials from file ",
                                     credentials_path));
  }
  // Creating "empty" 'channel_creds', to convert 'creds' to ChannelCredentials
  // via CompositeChannelCredentials().
  std::shared_ptr<grpc::ChannelCredentials> channel_creds =
      grpc::SslCredentials(grpc::SslCredentialsOptions());
  return grpc::CompositeChannelCredentials(channel_creds, creds);
}

// Returns GCP KMS key name contained in `key_uri`. If `key_uri` does not refer
// to a GCP key, returns an error status.
util::StatusOr<std::string> GetKeyName(absl::string_view key_uri) {
  if (!absl::StartsWithIgnoreCase(key_uri, kKeyUriPrefix)) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("The key URI ", key_uri,
                                     " does not start with ", kKeyUriPrefix));
  }
  return std::string(key_uri.substr(kKeyUriPrefix.length()));
}

}  // namespace

util::StatusOr<std::unique_ptr<GcpKmsClient>> GcpKmsClient::New(
    absl::string_view key_uri, absl::string_view credentials_path) {
  // Empty key name by default.
  std::string key_name = "";
  if (!key_uri.empty()) {
    util::StatusOr<std::string> key_name_from_uri = GetKeyName(key_uri);
    if (!key_name_from_uri.ok()) {
      return key_name_from_uri.status();
    }
    key_name = key_name_from_uri.value();
  }

  // Read credentials.
  util::StatusOr<std::shared_ptr<grpc::ChannelCredentials>> creds_result =
      GetCredentials(credentials_path);
  if (!creds_result.ok()) {
    return creds_result.status();
  }

  // Create a KMS stub.
  grpc::ChannelArguments args;
  args.SetUserAgentPrefix(
      absl::StrCat(kTinkUserAgentPrefix, Version::kTinkVersion, " CPP"));
  std::shared_ptr<KeyManagementService::Stub> kms_stub =
      KeyManagementService::NewStub(grpc::CreateCustomChannel(
          std::string(kGcpKmsServer), creds_result.value(), args));
  return absl::WrapUnique(new GcpKmsClient(key_name, std::move(kms_stub)));
}

bool GcpKmsClient::DoesSupport(absl::string_view key_uri) const {
  util::StatusOr<std::string> key_name = GetKeyName(key_uri);
  if (!key_name.ok()) {
    return false;
  }
  return key_name_.empty() ? true : key_name_ == *key_name;
}

util::StatusOr<std::unique_ptr<Aead>> GcpKmsClient::GetAead(
    absl::string_view key_uri) const {
  util::StatusOr<std::string> key_name_from_key_uri = GetKeyName(key_uri);
  // key_uri is invalid.
  if (!key_name_from_key_uri.ok()) {
    return key_name_from_key_uri.status();
  }
  // key_uri is valid, but if key_name_ is not empty key_name_from_key_uri must
  // be equal to key_name_.
  if (!key_name_.empty() && key_name_ != *key_name_from_key_uri) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        absl::StrCat("This client is bound to ", key_name_,
                                     " and cannot use key ", key_uri));
  }
  return GcpKmsAead::New(*key_name_from_key_uri, kms_stub_);
}

util::Status GcpKmsClient::RegisterNewClient(
    absl::string_view key_uri, absl::string_view credentials_path) {
  auto client_result = GcpKmsClient::New(key_uri, credentials_path);
  if (!client_result.ok()) {
    return client_result.status();
  }
  return KmsClients::Add(std::move(client_result.value()));
}

}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
