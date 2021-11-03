// Copyright 2018 Google Inc.
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

#include "tink/json_keyset_writer.h"

#include <ostream>
#include <istream>
#include <sstream>

#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "include/rapidjson/document.h"
#include "include/rapidjson/prettywriter.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/protobuf_helper.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"


namespace crypto {
namespace tink {


using google::crypto::tink::EncryptedKeyset;
using google::crypto::tink::KeyData;
using google::crypto::tink::Keyset;
using google::crypto::tink::KeysetInfo;
using util::Enums;

namespace {

// Helpers for transoforming Keyset-protos to  JSON strings.
util::Status ToJson(const KeyData& key_data,
                        rapidjson::Value* json_key_data,
                        rapidjson::Document::AllocatorType* allocator) {
  rapidjson::Value type_url(rapidjson::kStringType);
  type_url.SetString(key_data.type_url().c_str(), *allocator);
  json_key_data->AddMember("typeUrl", type_url, *allocator);

  rapidjson::Value material_type(rapidjson::kStringType);
  material_type.SetString(Enums::KeyMaterialName(key_data.key_material_type()),
                          *allocator);
  json_key_data->AddMember("keyMaterialType", material_type, *allocator);

  std::string base64_string;
  absl::Base64Escape(key_data.value(), &base64_string);
  rapidjson::Value key_value(rapidjson::kStringType);
  key_value.SetString(base64_string.c_str(), *allocator);
  json_key_data->AddMember("value", key_value, *allocator);

  return util::OkStatus();
}

util::Status ToJson(const Keyset::Key& key,
                        rapidjson::Value* json_key,
                        rapidjson::Document::AllocatorType* allocator) {
  rapidjson::Value key_id(rapidjson::kNumberType);
  key_id.SetUint(key.key_id());
  json_key->AddMember("keyId", key_id, *allocator);

  rapidjson::Value key_status(rapidjson::kStringType);
  key_status.SetString(Enums::KeyStatusName(key.status()), *allocator);
  json_key->AddMember("status", key_status, *allocator);

  rapidjson::Value prefix_type(rapidjson::kStringType);
  prefix_type.SetString(Enums::OutputPrefixName(key.output_prefix_type()),
                        *allocator);
  json_key->AddMember("outputPrefixType", prefix_type, *allocator);

  rapidjson::Value json_key_data(rapidjson::kObjectType);
  auto status = ToJson(key.key_data(), &json_key_data, allocator);
  if (!status.ok()) return status;
  json_key->AddMember("keyData", json_key_data, *allocator);
  return util::OkStatus();
}

util::StatusOr<std::string> ToJsonString(const Keyset& keyset) {
  rapidjson::Document json_doc(rapidjson::kObjectType);
  auto& allocator = json_doc.GetAllocator();

  rapidjson::Value primary_key_id(rapidjson::kNumberType);
  primary_key_id.SetUint(keyset.primary_key_id());
  json_doc.AddMember("primaryKeyId", primary_key_id, allocator);

  rapidjson::Value key_array(rapidjson::kArrayType);
  for (const Keyset::Key& key : keyset.key()) {
    rapidjson::Value json_key(rapidjson::kObjectType);
    auto status = ToJson(key, &json_key, &allocator);
    if (!status.ok()) return status;
    key_array.PushBack(json_key, allocator);
  }
  json_doc.AddMember("key", key_array, allocator);
  rapidjson::StringBuffer string_buffer;
  rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(string_buffer);
  json_doc.Accept(writer);
  return std::string(string_buffer.GetString());
}

util::Status ToJson(const KeysetInfo::KeyInfo& key_info,
                        rapidjson::Value* json_key_info,
                        rapidjson::Document::AllocatorType* allocator) {
  rapidjson::Value type_url(rapidjson::kStringType);
  type_url.SetString(key_info.type_url().c_str(), *allocator);
  json_key_info->AddMember("typeUrl", type_url, *allocator);

  rapidjson::Value key_id(rapidjson::kNumberType);
  key_id.SetUint(key_info.key_id());
  json_key_info->AddMember("keyId", key_id, *allocator);

  rapidjson::Value key_status(rapidjson::kStringType);
  key_status.SetString(Enums::KeyStatusName(key_info.status()), *allocator);
  json_key_info->AddMember("status", key_status, *allocator);

  rapidjson::Value prefix_type(rapidjson::kStringType);
  prefix_type.SetString(Enums::OutputPrefixName(key_info.output_prefix_type()),
                        *allocator);
  json_key_info->AddMember("outputPrefixType", prefix_type, *allocator);
  return util::OkStatus();
}

util::Status ToJson(const KeysetInfo& keyset_info,
                        rapidjson::Value* json_keyset_info,
                        rapidjson::Document::AllocatorType* allocator) {
  rapidjson::Value primary_key_id(rapidjson::kNumberType);
  primary_key_id.SetUint(keyset_info.primary_key_id());
  json_keyset_info->AddMember("primaryKeyId", primary_key_id, *allocator);

  rapidjson::Value key_info_array(rapidjson::kArrayType);
  for (const KeysetInfo::KeyInfo& key_info : keyset_info.key_info()) {
    rapidjson::Value json_key_info(rapidjson::kObjectType);
    auto status = ToJson(key_info, &json_key_info, allocator);
    if (!status.ok()) return status;
    key_info_array.PushBack(json_key_info, *allocator);
  }
  json_keyset_info->AddMember("keyInfo", key_info_array, *allocator);
  return util::OkStatus();
}

util::StatusOr<std::string> ToJsonString(const EncryptedKeyset& keyset) {
  rapidjson::Document json_doc(rapidjson::kObjectType);
  auto& allocator = json_doc.GetAllocator();

  std::string base64_string;
  absl::Base64Escape(keyset.encrypted_keyset(), &base64_string);
  rapidjson::Value encrypted_keyset(rapidjson::kStringType);
  encrypted_keyset.SetString(base64_string.c_str(), allocator);
  json_doc.AddMember("encryptedKeyset", encrypted_keyset, allocator);

  if (keyset.has_keyset_info()) {
    rapidjson::Value json_keyset_info(rapidjson::kObjectType);
    auto status = ToJson(keyset.keyset_info(), &json_keyset_info, &allocator);
    if (!status.ok()) return status;
    json_doc.AddMember("keysetInfo", json_keyset_info, allocator);
  }

  rapidjson::StringBuffer string_buffer;
  rapidjson::PrettyWriter<rapidjson::StringBuffer> writer(string_buffer);
  json_doc.Accept(writer);
  return std::string(string_buffer.GetString());
}

util::Status WriteData(absl::string_view data, std::ostream* destination) {
  (*destination) << data;
  if (destination->fail()) {
    return util::Status(util::error::UNKNOWN,
                            "Error writing to the destination stream.");
  }
  return util::OkStatus();
}

}  // anonymous namespace


//  static
util::StatusOr<std::unique_ptr<JsonKeysetWriter>> JsonKeysetWriter::New(
    std::unique_ptr<std::ostream> destination_stream) {
  if (destination_stream == nullptr) {
    return util::Status(absl::StatusCode::kInvalidArgument,
                        "destination_stream must be non-null.");
  }
  std::unique_ptr<JsonKeysetWriter> writer(
      new JsonKeysetWriter(std::move(destination_stream)));
  return std::move(writer);
}

util::Status JsonKeysetWriter::Write(const Keyset& keyset) {
  auto json_string_result = ToJsonString(keyset);
  if (!json_string_result.ok()) return json_string_result.status();
  return WriteData(json_string_result.ValueOrDie(), destination_stream_.get());
}

util::Status JsonKeysetWriter::Write(
    const EncryptedKeyset& encrypted_keyset) {
  auto json_string_result = ToJsonString(encrypted_keyset);
  if (!json_string_result.ok()) return json_string_result.status();
  return WriteData(json_string_result.ValueOrDie(), destination_stream_.get());
}

}  // namespace tink
}  // namespace crypto
