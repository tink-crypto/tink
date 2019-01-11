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
#ifndef TINK_CORE_KEY_MANAGER_BASE_H_
#define TINK_CORE_KEY_MANAGER_BASE_H_

#include <memory>
#include <string>

#include "absl/base/casts.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "tink/key_manager.h"
#include "tink/util/constants.h"
#include "tink/util/errors.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

template <typename KeyProto, typename KeyFormatProto>
class KeyFactoryBase : public virtual KeyFactory {
 public:
  KeyFactoryBase() {}

  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(const portable_proto::MessageLite& key_format) const override {
    if (key_format.GetTypeName() != KeyFormatProto().GetTypeName()) {
      return crypto::tink::util::Status(
          util::error::INVALID_ARGUMENT,
          absl::StrCat("Key format proto '", key_format.GetTypeName(),
                       "' is not supported by this manager."));
    }
    crypto::tink::util::StatusOr<std::unique_ptr<KeyProto>> new_key_result =
        NewKeyFromFormat(static_cast<const KeyFormatProto&>(key_format));
    if (!new_key_result.ok()) return new_key_result.status();
    return absl::implicit_cast<std::unique_ptr<portable_proto::MessageLite>>(
        std::move(new_key_result.ValueOrDie()));
  }

  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(absl::string_view serialized_key_format) const override {
    KeyFormatProto key_format;
    if (!key_format.ParseFromString(std::string(serialized_key_format))) {
      return crypto::tink::util::Status(
          util::error::INVALID_ARGUMENT,
          absl::StrCat("Could not parse the passed string as proto '",
                       KeyFormatProto().GetTypeName(), "'."));
    }
    return NewKey(key_format);
  }

  crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  NewKeyData(absl::string_view serialized_key_format) const override {
    auto new_key_result = NewKey(serialized_key_format);
    if (!new_key_result.ok()) return new_key_result.status();
    auto new_key =
        static_cast<const KeyProto&>(*(new_key_result.ValueOrDie()));
    auto key_data = absl::make_unique<google::crypto::tink::KeyData>();
    key_data->set_type_url(
        absl::StrCat(kTypeGoogleapisCom, KeyProto().GetTypeName()));
    key_data->set_value(new_key.SerializeAsString());
    key_data->set_key_material_type(key_material_type());
    return std::move(key_data);
  }

  virtual google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const = 0;

 protected:
  virtual crypto::tink::util::StatusOr<std::unique_ptr<KeyProto>>
  NewKeyFromFormat(const KeyFormatProto& format) const = 0;
};

template <typename Primitive, typename KeyProto>
class KeyManagerBase : public KeyManager<Primitive> {
 public:
  // Constructs an instance of Primitive for the given 'key_data'.
  crypto::tink::util::StatusOr<std::unique_ptr<Primitive>> GetPrimitive(
      const google::crypto::tink::KeyData& key_data) const override {
    if (this->DoesSupport(key_data.type_url())) {
      KeyProto key_proto;
      if (!key_proto.ParseFromString(key_data.value())) {
        return ToStatusF(util::error::INVALID_ARGUMENT,
                         "Could not parse key_data.value as key type '%s'.",
                         key_data.type_url().c_str());
      }
      return GetPrimitiveFromKey(key_proto);
    } else {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Key type '%s' is not supported by this manager.",
                       key_data.type_url().c_str());
    }
  }

  // Constructs an instance of Primitive for the given 'key'.
  crypto::tink::util::StatusOr<std::unique_ptr<Primitive>> GetPrimitive(
      const portable_proto::MessageLite& key) const override {
    std::string key_type = absl::StrCat(kTypeGoogleapisCom, key.GetTypeName());
    if (this->DoesSupport(key_type)) {
      const KeyProto& key_proto = static_cast<const KeyProto&>(key);
      return GetPrimitiveFromKey(key_proto);
    } else {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Key type '%s' is not supported by this manager.",
                       key_type.c_str());
    }
  }

  const std::string& get_key_type() const override {
    return KeyManagerBase::static_key_type();
  }

  static std::string& static_key_type() {
    static std::string* key_type =
        new std::string(absl::StrCat(kTypeGoogleapisCom, KeyProto().GetTypeName()));
    return *key_type;
  }

 protected:
  virtual crypto::tink::util::StatusOr<std::unique_ptr<Primitive>>
  GetPrimitiveFromKey(const KeyProto& key_proto) const = 0;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_CORE_KEY_MANAGER_BASE_H_
