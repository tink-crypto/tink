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

#include "tink/json_keyset_reader.h"

#include <iostream>
#include <istream>
#include <sstream>

#include "absl/memory/memory.h"
#include "absl/strings/escaping.h"
#include "include/rapidjson/document.h"
#include "include/rapidjson/error/en.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace tinkutil = crypto::tink::util;

namespace crypto {
namespace tink {

using google::crypto::tink::EncryptedKeyset;
using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeysetInfo;
using crypto::tink::util::Enums;

namespace {


// Helpers for validating and parsing JSON strings with EncryptedKeyset-protos.
tinkutil::Status ValidateEncryptedKeyset(const rapidjson::Document& json_doc) {
  if (!json_doc.HasMember("encryptedKeyset") ||
      !json_doc["encryptedKeyset"].IsString() ||
      (json_doc.HasMember("keysetInfo") &&
       !json_doc["keysetInfo"].IsObject())) {
    return tinkutil::Status(tinkutil::error::INVALID_ARGUMENT,
                            "Invalid JSON EncryptedKeyset");
  }
  return tinkutil::Status::OK;
}

tinkutil::Status ValidateKeysetInfo(const rapidjson::Value& json_value) {
  if (!json_value.HasMember("primaryKeyId") ||
      !json_value["primaryKeyId"].IsUint() ||
      !json_value.HasMember("keyInfo") ||
      !json_value["keyInfo"].IsArray() ||
      json_value["keyInfo"].Size() < 1) {
    return tinkutil::Status(tinkutil::error::INVALID_ARGUMENT,
                            "Invalid JSON KeysetInfo");
  }
  return tinkutil::Status::OK;
}

tinkutil::Status ValidateKeyInfo(const rapidjson::Value& json_value) {
  if (!json_value.HasMember("typeUrl") ||
      !json_value["typeUrl"].IsString() ||
      !json_value.HasMember("status") ||
      !json_value["status"].IsString() ||
      !json_value.HasMember("keyId") ||
      !json_value["keyId"].IsUint() ||
      !json_value.HasMember("outputPrefixType") ||
      !json_value["outputPrefixType"].IsString()) {
    return tinkutil::Status(tinkutil::error::INVALID_ARGUMENT,
                            "Invalid JSON KeyInfo");
  }
  return tinkutil::Status::OK;
}

tinkutil::StatusOr<std::unique_ptr<KeysetInfo::KeyInfo>>
KeyInfoFromJson(const rapidjson::Value& json_value) {
  auto status = ValidateKeyInfo(json_value);
  if (!status.ok()) return status;

  auto key_info = absl::make_unique<KeysetInfo::KeyInfo>();
  key_info->set_type_url(json_value["typeUrl"].GetString());
  key_info->set_status(Enums::KeyStatus(json_value["status"].GetString()));
  key_info->set_key_id(json_value["keyId"].GetUint());
  key_info->set_output_prefix_type(
      Enums::OutputPrefix(json_value["outputPrefixType"].GetString()));
  return std::move(key_info);
}

tinkutil::StatusOr<std::unique_ptr<KeysetInfo>>
KeysetInfoFromJson(const rapidjson::Value& json_value) {
  auto status = ValidateKeysetInfo(json_value);
  if (!status.ok()) return status;
  auto keyset_info = absl::make_unique<KeysetInfo>();
  keyset_info->set_primary_key_id(json_value["primaryKeyId"].GetUint());
  for (const auto& json_key_info : json_value["keyInfo"].GetArray()) {
    auto key_info_result = KeyInfoFromJson(json_key_info);
    if (!key_info_result.ok()) return key_info_result.status();
    *(keyset_info->add_key_info()) = *(key_info_result.ValueOrDie());
  }
  return std::move(keyset_info);
}

tinkutil::StatusOr<std::unique_ptr<EncryptedKeyset>>
EncryptedKeysetFromJson(const rapidjson::Document& json_doc) {
  auto status = ValidateEncryptedKeyset(json_doc);
  if (!status.ok()) return status;
  std::string enc_keyset;
  if (!absl::Base64Unescape(
          json_doc["encryptedKeyset"].GetString(), &enc_keyset)) {
    return tinkutil::Status(tinkutil::error::INVALID_ARGUMENT,
                            "Invalid JSON EncryptedKeyset");
  }
  auto encrypted_keyset = absl::make_unique<EncryptedKeyset>();
  encrypted_keyset->set_encrypted_keyset(enc_keyset);
  if (json_doc.HasMember("keysetInfo")) {
    auto keyset_info_result =
        KeysetInfoFromJson(json_doc["keysetInfo"]);
    if (!keyset_info_result.ok()) {
      return keyset_info_result.status();
    }
    *(encrypted_keyset->mutable_keyset_info()) =
        *(keyset_info_result.ValueOrDie());
  }
  return std::move(encrypted_keyset);
}

// Helpers for validating and parsing JSON strings with Keyset-protos.
tinkutil::Status ValidateKeyset(const rapidjson::Document& json_doc) {
  if (!json_doc.HasMember("primaryKeyId") ||
      !json_doc["primaryKeyId"].IsUint() ||
      !json_doc.HasMember("key") ||
      !json_doc["key"].IsArray() ||
      json_doc["key"].Size() < 1) {
    return tinkutil::Status(tinkutil::error::INVALID_ARGUMENT,
                            "Invalid JSON Keyset");
  }
  return tinkutil::Status::OK;
}

tinkutil::Status ValidateKey(const rapidjson::Value& json_value) {
  if (!json_value.HasMember("keyData") ||
      !json_value["keyData"].IsObject() ||
      !json_value.HasMember("status") ||
      !json_value["status"].IsString() ||
      !json_value.HasMember("keyId") ||
      !json_value["keyId"].IsUint() ||
      !json_value.HasMember("outputPrefixType") ||
      !json_value["outputPrefixType"].IsString()) {
    return tinkutil::Status(tinkutil::error::INVALID_ARGUMENT,
                            "Invalid JSON Key");
  }
  return tinkutil::Status::OK;
}

tinkutil::Status ValidateKeyData(const rapidjson::Value& json_value) {
  if (!json_value.HasMember("typeUrl") ||
      !json_value["typeUrl"].IsString() ||
      !json_value.HasMember("value") ||
      !json_value["value"].IsString() ||
      !json_value.HasMember("keyMaterialType") ||
      !json_value["keyMaterialType"].IsString()) {
    return tinkutil::Status(tinkutil::error::INVALID_ARGUMENT,
                            "Invalid JSON KeyData");
  }
  return tinkutil::Status::OK;
}

tinkutil::StatusOr<std::unique_ptr<KeyData>>
KeyDataFromJson(const rapidjson::Value& json_value) {
  auto status = ValidateKeyData(json_value);
  if (!status.ok()) return status;
  std::string value_field;
  if (!absl::Base64Unescape(json_value["value"].GetString(), &value_field)) {
    return tinkutil::Status(tinkutil::error::INVALID_ARGUMENT,
                            "Invalid JSON KeyData");
  }
  auto key_data = absl::make_unique<KeyData>();
  key_data->set_type_url(json_value["typeUrl"].GetString());
  key_data->set_value(value_field);
  key_data->set_key_material_type(
      Enums::KeyMaterial(json_value["keyMaterialType"].GetString()));
  return std::move(key_data);
}

tinkutil::StatusOr<std::unique_ptr<Keyset::Key>>
KeyFromJson(const rapidjson::Value& json_value) {
  auto status = ValidateKey(json_value);
  if (!status.ok()) return status;
  auto key_data_result = KeyDataFromJson(json_value["keyData"]);
  if (!key_data_result.ok()) return key_data_result.status();

  auto key = absl::make_unique<Keyset::Key>();
  key->set_key_id(json_value["keyId"].GetUint());
  key->set_status(Enums::KeyStatus(json_value["status"].GetString()));
  key->set_output_prefix_type(
      Enums::OutputPrefix(json_value["outputPrefixType"].GetString()));
  *(key->mutable_key_data()) = *(key_data_result.ValueOrDie());
  return std::move(key);
}

tinkutil::StatusOr<std::unique_ptr<Keyset>>
KeysetFromJson(const rapidjson::Document& json_doc) {
  auto status = ValidateKeyset(json_doc);
  if (!status.ok()) return status;
  auto keyset = absl::make_unique<Keyset>();
  keyset->set_primary_key_id(json_doc["primaryKeyId"].GetUint());
  for (const auto& json_key : json_doc["key"].GetArray()) {
    auto key_result = KeyFromJson(json_key);
    if (!key_result.ok()) return key_result.status();
    *(keyset->add_key()) = *(key_result.ValueOrDie());
  }
  return std::move(keyset);
}

}  // namespace


//  static
tinkutil::StatusOr<std::unique_ptr<KeysetReader>> JsonKeysetReader::New(
    std::unique_ptr<std::istream> keyset_stream) {
  if (keyset_stream == nullptr) {
    return tinkutil::Status(tinkutil::error::INVALID_ARGUMENT,
                            "keyset_stream must be non-null.");
  }
  std::unique_ptr<KeysetReader> reader(
      new JsonKeysetReader(std::move(keyset_stream)));
  return std::move(reader);
}

//  static
tinkutil::StatusOr<std::unique_ptr<KeysetReader>> JsonKeysetReader::New(
    absl::string_view serialized_keyset) {
  std::unique_ptr<KeysetReader> reader(new JsonKeysetReader(serialized_keyset));
  return std::move(reader);
}

tinkutil::StatusOr<std::unique_ptr<Keyset>> JsonKeysetReader::Read() {
  std::string serialized_keyset_from_stream;
  std::string* serialized_keyset;
  if (keyset_stream_ == nullptr) {
    serialized_keyset = &serialized_keyset_;
  } else {
    serialized_keyset_from_stream = std::string(
        std::istreambuf_iterator<char>(*keyset_stream_), {});
    serialized_keyset = &serialized_keyset_from_stream;
  }
  rapidjson::Document json_doc(rapidjson::kObjectType);
  if (json_doc.Parse(serialized_keyset->c_str()).HasParseError()) {
    return ToStatusF(tinkutil::error::INVALID_ARGUMENT,
                     "Invalid JSON Keyset: Error (offset %u): %s",
                     static_cast<unsigned>(json_doc.GetErrorOffset()),
                     rapidjson::GetParseError_En(json_doc.GetParseError()));
  }
  return KeysetFromJson(json_doc);
}

tinkutil::StatusOr<std::unique_ptr<EncryptedKeyset>>
JsonKeysetReader::ReadEncrypted() {
  std::string serialized_keyset_from_stream;
  std::string* serialized_keyset;
  if (keyset_stream_ == nullptr) {
    serialized_keyset = &serialized_keyset_;
  } else {
    serialized_keyset_from_stream = std::string(
        std::istreambuf_iterator<char>(*keyset_stream_), {});
    serialized_keyset = &serialized_keyset_from_stream;
  }
  rapidjson::Document json_doc;
  if (json_doc.Parse(serialized_keyset->c_str()).HasParseError()) {
    return ToStatusF(tinkutil::error::INVALID_ARGUMENT,
                     "Invalid JSON EncryptedKeyset: Error (offset %u): %s",
                     static_cast<unsigned>(json_doc.GetErrorOffset()),
                     rapidjson::GetParseError_En(json_doc.GetParseError()));
  }
  return EncryptedKeysetFromJson(json_doc);
}

}  // namespace tink
}  // namespace crypto
