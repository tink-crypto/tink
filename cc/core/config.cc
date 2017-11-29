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

#include "cc/config.h"

#include "cc/mac.h"
#include "cc/aead.h"
#include "cc/hybrid_decrypt.h"
#include "cc/hybrid_encrypt.h"
#include "cc/public_key_sign.h"
#include "cc/public_key_verify.h"
#include "absl/strings/ascii.h"
#include "cc/util/errors.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "proto/config.pb.h"

using google::crypto::tink::KeyTypeEntry;

namespace crypto {
namespace tink {

// static
std::unique_ptr<google::crypto::tink::KeyTypeEntry>
Config::GetTinkKeyTypeEntry(const std::string& catalogue_name,
                            const std::string& primitive_name,
                            const std::string& key_proto_name,
                            int key_manager_version,
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
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Missing type_url.");
  }
  if (entry.primitive_name().empty()) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Missing primitive_name.");
  }
  if (entry.catalogue_name().empty()) {
    return util::Status(util::error::INVALID_ARGUMENT,
                        "Missing catalogue_name.");
  }
  return util::Status::OK;
}

// static
util::Status Config::Register(
    const google::crypto::tink::RegistryConfig& config) {
  for (const auto& entry : config.entry()) {
    util::Status status;
    std::string primitive_name = absl::AsciiStrToLower(entry.primitive_name());

    if (primitive_name == "mac") {
      status = Register<Mac>(entry);
    } else if (primitive_name == "aead") {
      status = Register<Aead>(entry);
    } else if (primitive_name == "hybriddecrypt") {
      status = Register<HybridDecrypt>(entry);
    } else if (primitive_name == "hybridencrypt") {
      status = Register<HybridEncrypt>(entry);
    } else if (primitive_name == "publickeysign") {
      status = Register<PublicKeySign>(entry);
    } else if (primitive_name == "publickeyverify") {
      status = Register<PublicKeyVerify>(entry);
    } else {
      status = ToStatusF(crypto::tink::util::error::INVALID_ARGUMENT,
                         "A non-standard primitive '%s' '%s', "
                         "use directly Config::Register<P>(KeyTypeEntry&).",
                         entry.primitive_name().c_str(),
                         primitive_name.c_str()
                         );
    }
    if (!status.ok()) return status;
  }
  return util::Status::OK;
}

}  // namespace tink
}  // namespace crypto
