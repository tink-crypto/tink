// Copyright 2017 Google Inc.
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

#include "tink/config.h"

#include <string>

#include "absl/status/status.h"
#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/config.pb.h"

using google::crypto::tink::KeyTypeEntry;

namespace crypto {
namespace tink {

// static
std::unique_ptr<google::crypto::tink::KeyTypeEntry> Config::GetTinkKeyTypeEntry(
    const std::string& catalogue_name, const std::string& primitive_name,
    const std::string& key_proto_name, int key_manager_version,
    bool new_key_allowed) {
  std::string prefix = "type.googleapis.com/google.crypto.tink.";
  std::unique_ptr<KeyTypeEntry> entry(new KeyTypeEntry());
  entry->set_catalogue_name(catalogue_name);
  entry->set_primitive_name(primitive_name);
  entry->set_type_url(prefix.append(key_proto_name));
  entry->set_key_manager_version(key_manager_version);
  entry->set_new_key_allowed(new_key_allowed);
  return entry;
}

// static
crypto::tink::util::Status Config::Validate(const KeyTypeEntry& entry) {
  if (entry.type_url().empty()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Missing type_url.");
  }
  if (entry.primitive_name().empty()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Missing primitive_name.");
  }
  if (entry.catalogue_name().empty()) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "Missing catalogue_name.");
  }
  return util::OkStatus();
}

// static
util::Status Config::Register(
    const google::crypto::tink::RegistryConfig& config) {
  util::Status status;
  status = MacConfig::Register();
  if (!status.ok()) return status;
  status = AeadConfig::Register();
  if (!status.ok()) return status;
  status = DeterministicAeadConfig::Register();
  if (!status.ok()) return status;
  status = HybridConfig::Register();
  if (!status.ok()) return status;
  status = SignatureConfig::Register();
  if (!status.ok()) return status;
  status = StreamingAeadConfig::Register();
  if (!status.ok()) return status;
  return util::OkStatus();
}

}  // namespace tink
}  // namespace crypto
