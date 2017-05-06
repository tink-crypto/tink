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

#include "cc/util/test_util.h"

#include <stdarg.h>
#include <stdlib.h>

#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "google/protobuf/stubs/stringpiece.h"
#include "proto/tink.pb.h"

using google::cloud::crypto::tink::Keyset;
using google::cloud::crypto::tink::OutputPrefixType;
using util::error::Code;
using util::Status;

namespace cloud {
namespace crypto {
namespace tink {
namespace test {

util::StatusOr<std::string> HexDecode(google::protobuf::StringPiece hex) {
  if (hex.size() % 2 != 0) {
    return util::Status(util::error::INVALID_ARGUMENT, "Input has odd size.");
  }
  std::string decoded(hex.size() / 2, static_cast<char>(0));
  for (int i = 0; i < hex.size(); ++i) {
    char c = hex[i];
    char val;
    if ('0' <= c && c <= '9')
      val = c - '0';
    else if ('a' <= c && c <= 'f')
      val = c - 'a' + 10;
    else if ('A' <= c && c <= 'F')
      val = c - 'A' + 10;
    else
      return util::Status(util::error::INVALID_ARGUMENT, "Not hexadecimal");
    decoded[i / 2] = (decoded[i / 2] << 4) | val;
  }
  return decoded;
}

std::string HexEncode(google::protobuf::StringPiece bytes) {
  std::string hexchars = "0123456789abcdef";
  std::string res(bytes.size() * 2, static_cast<char>(255));
  for (int i = 0; i < bytes.size(); ++i) {
    uint8_t c = static_cast<uint8_t>(bytes[i]);
    res[2 * i] = hexchars[c / 16];
    res[2 * i + 1] = hexchars[c % 16];
  }
  return res;
}

void AddKey(
    const std::string& key_type,
    uint32_t key_id,
    const google::protobuf::Message& new_key,
    google::cloud::crypto::tink::OutputPrefixType output_prefix,
    google::cloud::crypto::tink::KeyStatusType key_status,
    google::cloud::crypto::tink::KeyData::KeyMaterialType material_type,
    google::cloud::crypto::tink::Keyset* keyset) {
  Keyset::Key* key = keyset->add_key();
  key->set_output_prefix_type(output_prefix);
  key->set_key_id(key_id);
  key->set_status(key_status);
  key->mutable_key_data()->set_type_url(key_type);
  key->mutable_key_data()->set_key_material_type(material_type);
  key->mutable_key_data()->set_value(new_key.SerializeAsString());
}

void AddTinkKey(
    const std::string& key_type,
    uint32_t key_id,
    const google::protobuf::Message& key,
    google::cloud::crypto::tink::KeyStatusType key_status,
    google::cloud::crypto::tink::KeyData::KeyMaterialType material_type,
    google::cloud::crypto::tink::Keyset* keyset) {
  AddKey(key_type, key_id, key, OutputPrefixType::TINK,
         key_status, material_type, keyset);
}

void AddLegacyKey(
    const std::string& key_type,
    uint32_t key_id,
    const google::protobuf::Message& key,
    google::cloud::crypto::tink::KeyStatusType key_status,
    google::cloud::crypto::tink::KeyData::KeyMaterialType material_type,
    google::cloud::crypto::tink::Keyset* keyset) {
  AddKey(key_type, key_id, key, OutputPrefixType::LEGACY,
         key_status, material_type, keyset);
}

void AddRawKey(
    const std::string& key_type,
    uint32_t key_id,
    const google::protobuf::Message& key,
    google::cloud::crypto::tink::KeyStatusType key_status,
    google::cloud::crypto::tink::KeyData::KeyMaterialType material_type,
    google::cloud::crypto::tink::Keyset* keyset) {
  AddKey(key_type, key_id, key, OutputPrefixType::RAW,
         key_status, material_type, keyset);
}

}  // namespace test
}  // namespace tink
}  // namespace crypto
}  // namespace cloud
