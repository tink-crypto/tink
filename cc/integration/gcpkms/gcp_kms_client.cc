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
#include <sstream>

#include "grpcpp/channel.h"
#include "grpcpp/create_channel.h"
#include "grpcpp/security/credentials.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "tink/integration/gcpkms/gcp_kms_aead.h"
#include "tink/kms_clients.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/version.h"

namespace crypto {
namespace tink {
namespace integration {
namespace gcpkms {

namespace {

using crypto::tink::ToStatusF;
using crypto::tink::Version;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;
using google::cloud::kms::v1::KeyManagementService;
using grpc::ChannelArguments;
using grpc::ChannelCredentials;

static constexpr char kKeyUriPrefix[] = "gcp-kms://";
static constexpr char kGcpKmsServer[] = "cloudkms.googleapis.com";
static constexpr char kTinkUserAgentPrefix[] = "Tink/";

StatusOr<std::string> ReadFile(absl::string_view filename) {
  std::ifstream input_stream;
  input_stream.open(std::string(filename), std::ifstream::in);
  if (!input_stream.is_open()) {
    return ToStatusF(util::error::INVALID_ARGUMENT, "Error reading file %s",
                     filename);
  }
  std::stringstream input;
  input << input_stream.rdbuf();
  input_stream.close();
  return input.str();
}

StatusOr<std::shared_ptr<ChannelCredentials>> GetCredentials(
    absl::string_view credentials_path) {
  if (credentials_path.empty()) {
    auto creds = grpc::GoogleDefaultCredentials();
    if (creds == nullptr) {
      return Status(absl::StatusCode::kInternal,
                    "Could not read default credentials");
    }
    return creds;
  }

  // Try reading credentials from a file.
  auto json_creds_result = ReadFile(credentials_path);
  if (!json_creds_result.ok()) return json_creds_result.status();
  auto creds = grpc::ServiceAccountJWTAccessCredentials(
      json_creds_result.ValueOrDie());
  if (creds != nullptr) {
    // Creating "empty" 'channel_creds', to convert 'creds'
    // to ChannelCredentials via CompositeChannelCredentials().
    auto channel_creds = grpc::SslCredentials(grpc::SslCredentialsOptions());
    return grpc::CompositeChannelCredentials(channel_creds, creds);
  }
  return ToStatusF(util::error::INVALID_ARGUMENT,
                   "Could not load credentials from file %s", credentials_path);
}

// Returns GCP KMS key name contained in 'key_uri'.
// If 'key_uri' does not refer to an GCP key, returns an empty string.
std::string GetKeyName(absl::string_view key_uri) {
  if (!absl::StartsWithIgnoreCase(key_uri, kKeyUriPrefix)) return "";
  return std::string(key_uri.substr(std::string(kKeyUriPrefix).length()));
}

}  // namespace

// static
StatusOr<std::unique_ptr<GcpKmsClient>>
GcpKmsClient::New(absl::string_view key_uri,
                  absl::string_view credentials_path) {
  std::unique_ptr<GcpKmsClient> client(new GcpKmsClient());

  // If a specific key is given, create a GCP KMSClient.
  if (!key_uri.empty()) {
    client->key_name_ = GetKeyName(key_uri);
    if (client->key_name_.empty()) {
      return ToStatusF(util::error::INVALID_ARGUMENT, "Key '%s' not supported",
                       key_uri);
    }
  }
  // Read credentials.
  auto creds_result = GetCredentials(credentials_path);
  if (!creds_result.ok()) {
    return creds_result.status();
  }

  // Create a KMS stub.
  ChannelArguments args;
  args.SetUserAgentPrefix(
      absl::StrCat(kTinkUserAgentPrefix, Version::kTinkVersion, " CPP-Python"));
  client->kms_stub_ = KeyManagementService::NewStub(grpc::CreateCustomChannel(
      kGcpKmsServer, creds_result.ValueOrDie(), args));
  return std::move(client);
}

bool GcpKmsClient::DoesSupport(absl::string_view key_uri) const {
  if (!key_name_.empty()) {
    return key_name_ == GetKeyName(key_uri);
  }
  return !GetKeyName(key_uri).empty();
}

StatusOr<std::unique_ptr<Aead>>
GcpKmsClient::GetAead(absl::string_view key_uri) const {
  if (!DoesSupport(key_uri)) {
    if (!key_name_.empty()) {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "This client is bound to '%s', and cannot use key '%s'.",
                       key_name_, key_uri);
    } else {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "This client does not support key '%s'.", key_uri);
    }
  }
  if (!key_name_.empty()) {  // This client is bound to a specific key.
    return GcpKmsAead::New(key_name_, kms_stub_);
  } else {  // Create an GCP KMSClient for the given key.
    auto key_name = GetKeyName(key_uri);
    return GcpKmsAead::New(key_name, kms_stub_);
  }
}

Status GcpKmsClient::RegisterNewClient(absl::string_view key_uri,
                                       absl::string_view credentials_path) {
  auto client_result = GcpKmsClient::New(key_uri, credentials_path);
  if (!client_result.ok()) {
    return client_result.status();
  }

  return KmsClients::Add(std::move(client_result.ValueOrDie()));
}

}  // namespace gcpkms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
