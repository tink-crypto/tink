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

#include "tink/key_manager.h"
#include "tink/util/errors.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

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
    std::string key_type = std::string(kKeyTypePrefix) + key.GetTypeName();
    if (this->DoesSupport(key_type)) {
      const KeyProto& key_proto = static_cast<const KeyProto&>(key);
      return GetPrimitiveFromKey(key_proto);
    } else {
      return ToStatusF(util::error::INVALID_ARGUMENT,
                       "Key type '%s' is not supported by this manager.",
                       key_type.c_str());
    }
  }

 protected:
  virtual crypto::tink::util::StatusOr<std::unique_ptr<Primitive>>
  GetPrimitiveFromKey(const KeyProto& key_proto) const = 0;

 private:
  static constexpr char kKeyTypePrefix[] = "type.googleapis.com/";
};

template <typename P, typename KP>
constexpr char KeyManagerBase<P, KP>::kKeyTypePrefix[];

}  // namespace tink
}  // namespace crypto

#endif  // TINK_CORE_KEY_MANAGER_BASE_H_
