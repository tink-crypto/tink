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
#ifndef TINK_CORE_KEY_MANAGER_IMPL_H_
#define TINK_CORE_KEY_MANAGER_IMPL_H_

#include <functional>
#include <string>
#include <utility>

#include "absl/base/casts.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/core/key_type_manager.h"
#include "tink/key_manager.h"
#include "tink/util/constants.h"
#include "tink/util/status.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

// Template declaration of the class "KeyFactoryImpl" with a single template
// argument. We first declare it, then later give two "partial template
// specializations". This will imply that the KeyFactoryImpl can only be
// instantiated with arguments of the form KeyTypeManager<...>.
template <class KeyTypeManager>
class KeyFactoryImpl;

// First partial template specialization for KeyFactoryImpl: the given
// KeyTypeManager is of the form KeyTypeManager<KeyProto,
// KeyFormatProto, List<Primitives...>>.
template <class KeyProto, class KeyFormatProto, class... Primitives>
class KeyFactoryImpl<
    KeyTypeManager<KeyProto, KeyFormatProto, List<Primitives...>>>
    : public KeyFactory {
 public:
  explicit KeyFactoryImpl(KeyTypeManager<KeyProto, KeyFormatProto,
                                         List<Primitives...>>* key_type_manager)
      : key_type_manager_(key_type_manager) {}

  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(const portable_proto::MessageLite& key_format) const override {
    if (key_format.GetTypeName() != KeyFormatProto().GetTypeName()) {
      return crypto::tink::util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Key format proto '", key_format.GetTypeName(),
                       "' is not supported by this manager."));
    }
    auto validation = key_type_manager_->ValidateKeyFormat(
        static_cast<const KeyFormatProto&>(key_format));
    if (!validation.ok()) {
      return validation;
    }
    crypto::tink::util::StatusOr<KeyProto> new_key_result =
        key_type_manager_->CreateKey(
            static_cast<const KeyFormatProto&>(key_format));
    if (!new_key_result.ok()) return new_key_result.status();
    return absl::implicit_cast<std::unique_ptr<portable_proto::MessageLite>>(
        absl::make_unique<KeyProto>(std::move(new_key_result.value())));
  }

  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(absl::string_view serialized_key_format) const override {
    KeyFormatProto key_format;
    if (!key_format.ParseFromString(std::string(serialized_key_format))) {
      return crypto::tink::util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Could not parse the passed string as proto '",
                       KeyFormatProto().GetTypeName(), "'."));
    }
    auto validation = key_type_manager_->ValidateKeyFormat(key_format);
    if (!validation.ok()) {
      return validation;
    }
    return NewKey(static_cast<const portable_proto::MessageLite&>(key_format));
  }

  crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  NewKeyData(absl::string_view serialized_key_format) const override {
    auto new_key_result = NewKey(serialized_key_format);
    if (!new_key_result.ok()) return new_key_result.status();
    auto new_key = static_cast<const KeyProto&>(*(new_key_result.value()));
    auto key_data = absl::make_unique<google::crypto::tink::KeyData>();
    key_data->set_type_url(
        absl::StrCat(kTypeGoogleapisCom, KeyProto().GetTypeName()));
    key_data->set_value(new_key.SerializeAsString());
    key_data->set_key_material_type(key_type_manager_->key_material_type());
    return std::move(key_data);
  }

 private:
  KeyTypeManager<KeyProto, KeyFormatProto, List<Primitives...>>*
      key_type_manager_;
};

// Second partial template specialization for KeyFactoryImpl: the given
// KeyTypeManager is of the form KeyTypeManager<KeyProto, void,
// List<Primitives...>>.
template <class KeyProto, class... Primitives>
class KeyFactoryImpl<KeyTypeManager<KeyProto, void, List<Primitives...>>>
    : public KeyFactory {
 public:
  // We don't need the KeyTypeManager, but this is called from a template,
  // so the easiest way to ignore the argument is to provide a constructor which
  // ignores the argument.
  explicit KeyFactoryImpl(
      KeyTypeManager<KeyProto, void, List<Primitives...>>* key_type_manager) {}

  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(const portable_proto::MessageLite& key_format) const override {
    return util::Status(
        absl::StatusCode::kUnimplemented,
        "Creating new keys is not supported for this key manager.");
  }

  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(absl::string_view serialized_key_format) const override {
    return util::Status(
        absl::StatusCode::kUnimplemented,
        "Creating new keys is not supported for this key manager.");
  }

  crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  NewKeyData(absl::string_view serialized_key_format) const override {
    return util::Status(
        absl::StatusCode::kUnimplemented,
        "Creating new keys is not supported for this key manager.");
  }
};

// Template declaration of the class "KeyManagerImpl" with two template
// arguments. There is only one specialization which is defined, namely when
// the KeyTypeManager argument is of the form KeyTypeManager<KeyProto,
// KeyFormatProto, List<Primitives...>>. We don't provide a
// specialization for the case KeyFormatProto = void, so the compiler will pick
// this instantiation in this case.
template <class Primitive, class KeyTypeManager>
class KeyManagerImpl;

// The first template argument to the KeyManagerImpl is the primitive for which
// we should generate a KeyManager. The second is the KeyTypeManager, which
// takes itself template arguments. The list of the Primitives there must
// contain the first Primitive argument (otherwise there will be failures at
// runtime).
template <class Primitive, class KeyProto, class KeyFormatProto,
          class... Primitives>
class KeyManagerImpl<
    Primitive, KeyTypeManager<KeyProto, KeyFormatProto, List<Primitives...>>>
    : public KeyManager<Primitive> {
 public:
  explicit KeyManagerImpl(KeyTypeManager<KeyProto, KeyFormatProto,
                                         List<Primitives...>>* key_type_manager)
      : key_type_manager_(key_type_manager),
        key_factory_(
            absl::make_unique<KeyFactoryImpl<
                KeyTypeManager<KeyProto, KeyFormatProto, List<Primitives...>>>>(
                key_type_manager_)) {}

  // Constructs an instance of Primitive for the given 'key_data'.
  crypto::tink::util::StatusOr<std::unique_ptr<Primitive>> GetPrimitive(
      const google::crypto::tink::KeyData& key_data) const override {
    if (!this->DoesSupport(key_data.type_url())) {
      return ToStatusF(absl::StatusCode::kInvalidArgument,
                       "Key type '%s' is not supported by this manager.",
                       key_data.type_url());
    }
    KeyProto key_proto;
    if (!key_proto.ParseFromString(key_data.value())) {
      return ToStatusF(absl::StatusCode::kInvalidArgument,
                       "Could not parse key_data.value as key type '%s'.",
                       key_data.type_url());
    }
    auto validation = key_type_manager_->ValidateKey(key_proto);
    if (!validation.ok()) {
      return validation;
    }
    return key_type_manager_->template GetPrimitive<Primitive>(key_proto);
  }

  crypto::tink::util::StatusOr<std::unique_ptr<Primitive>> GetPrimitive(
      const portable_proto::MessageLite& key) const override {
    std::string key_type = absl::StrCat(kTypeGoogleapisCom, key.GetTypeName());
    if (!this->DoesSupport(key_type)) {
      return ToStatusF(absl::StatusCode::kInvalidArgument,
                       "Key type '%s' is not supported by this manager.",
                       key_type);
    }
    const KeyProto& key_proto = static_cast<const KeyProto&>(key);
    auto validation = key_type_manager_->ValidateKey(key_proto);
    if (!validation.ok()) {
      return validation;
    }
    return key_type_manager_->template GetPrimitive<Primitive>(key_proto);
  }

  uint32_t get_version() const override {
    return key_type_manager_->get_version();
  }

  const std::string& get_key_type() const override {
    return key_type_manager_->get_key_type();
  }

  const KeyFactory& get_key_factory() const override {
    return *key_factory_;
  }

 private:
  KeyTypeManager<KeyProto, KeyFormatProto, List<Primitives...>>*
      key_type_manager_;
  std::unique_ptr<KeyFactory> key_factory_;
};

// Helper function to create a KeyManager<Primitive> from a KeyTypeManager.
// Using this, all template arguments except the first one can be infered.
// Example:
//   std::unique_ptr<KeyManager<Aead>> km =
//     MakeKeyManager<Aead>(my_key_type_manager.get());
template <class Primitive, class KeyProto, class KeyFormatProto,
          class... Primitives>
std::unique_ptr<KeyManager<Primitive>> MakeKeyManager(
    KeyTypeManager<KeyProto, KeyFormatProto, List<Primitives...>>*
        key_type_manager) {
  return absl::make_unique<
      KeyManagerImpl<Primitive, KeyTypeManager<KeyProto, KeyFormatProto,
                                               List<Primitives...>>>>(
      key_type_manager);
}

// Creates a function which can derive a key, using the given KeyTypeManager.
// Note that the returned function stores a pointer to the given KeyTypeManager,
// which must remain valid for the lifetime of the function.
template <class KeyProto, class KeyFormatProto, class... Primitives>
std::function<crypto::tink::util::StatusOr<google::crypto::tink::KeyData>(
    absl::string_view, InputStream*)>
CreateDeriverFunctionFor(
    KeyTypeManager<KeyProto, KeyFormatProto, List<Primitives...>>*
        key_type_manager) {
  return [key_type_manager](absl::string_view serialized_key_format,
                            InputStream* randomness)
             -> crypto::tink::util::StatusOr<google::crypto::tink::KeyData> {
    KeyFormatProto key_format;
    if (!key_format.ParseFromString(std::string(serialized_key_format))) {
      return crypto::tink::util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Could not parse the passed string as proto '",
                       KeyFormatProto().GetTypeName(), "'."));
    }
    auto status = key_type_manager->ValidateKeyFormat(key_format);
    if (!status.ok()) {
      return status;
    }
    auto key_proto_or = key_type_manager->DeriveKey(key_format, randomness);
    if (!key_proto_or.ok()) {
      return key_proto_or.status();
    }
    status = key_type_manager->ValidateKey(key_proto_or.value());
    if (!status.ok()) {
      return status;
    }
    google::crypto::tink::KeyData result;
    result.set_type_url(key_type_manager->get_key_type());
    result.set_value(key_proto_or.value().SerializeAsString());
    result.set_key_material_type(key_type_manager->key_material_type());
    return std::move(result);
  };
}

// Template specialization of CreateDeriverFor in case the KeyTypeManager has
// KeyFormatProto = void, and hence there is no key derivation.
template <class KeyProto, class... Primitives>
std::function<crypto::tink::util::StatusOr<google::crypto::tink::KeyData>(
    absl::string_view, InputStream*)>
CreateDeriverFunctionFor(
    KeyTypeManager<KeyProto, void, List<Primitives...>>*
        key_type_manager) {
  return [key_type_manager](absl::string_view serialized_key_format,
                            InputStream* randomness)
             -> crypto::tink::util::StatusOr<google::crypto::tink::KeyData> {
    return crypto::tink::util::Status(
        absl::StatusCode::kUnimplemented,
        absl::StrCat("Registered KeyManager for type '",
                     key_type_manager->get_key_type(),
                     "' does not support key generation."));
  };
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_CORE_KEY_MANAGER_IMPL_H_
