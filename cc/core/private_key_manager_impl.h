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
#ifndef TINK_CORE_PRIVATE_KEY_MANAGER_IMPL_H_
#define TINK_CORE_PRIVATE_KEY_MANAGER_IMPL_H_

#include "absl/status/status.h"
#include "tink/core/key_manager_impl.h"
#include "tink/core/private_key_type_manager.h"
#include "tink/key_manager.h"
#include "tink/util/validation.h"
namespace crypto {
namespace tink {
namespace internal {

// An implementation of a PrivateKeyFactory given a corresponding internal
// private key manager and an internal (public) key manager.
// The template arguments PrivatePrimitivesList and PublicPrimitivesList should
// be of type List<Primitives...>. The assumption is that the given pointers in
// the constructor are of type
//   PrivateKeyTypeManager<PrivateKeyProto, PrivateKeyFormatProto,
//                             PublicKeyProto, PrivatePrimitivesList>
// and
//   KeyTypeManager<PublicKeyProto, void, PublicPrimitivesList>.
template <class PrivateKeyProto, class PrivateKeyFormatProto,
          class PublicKeyProto, class PrivatePrimitivesList,
          class PublicPrimitivesList>
class PrivateKeyFactoryImpl : public PrivateKeyFactory {
 public:
  PrivateKeyFactoryImpl(
      PrivateKeyTypeManager<PrivateKeyProto, PrivateKeyFormatProto,
                            PublicKeyProto, PrivatePrimitivesList>*
          private_key_manager,
      KeyTypeManager<PublicKeyProto, void, PublicPrimitivesList>*
          public_key_manager)
      : key_factory_impl_(private_key_manager),
        private_key_manager_(private_key_manager),
        public_key_type_(public_key_manager->get_key_type()),
        public_key_material_type_(public_key_manager->key_material_type()) {}

  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(const portable_proto::MessageLite& key_format) const override {
    return key_factory_impl_.NewKey(key_format);
  }

  crypto::tink::util::StatusOr<std::unique_ptr<portable_proto::MessageLite>>
  NewKey(absl::string_view serialized_key_format) const override {
    return key_factory_impl_.NewKey(serialized_key_format);
  }

  crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  NewKeyData(absl::string_view serialized_key_format) const override {
    return key_factory_impl_.NewKeyData(serialized_key_format);
  }

  crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::KeyData>>
  GetPublicKeyData(absl::string_view serialized_private_key) const override {
    PrivateKeyProto private_key;
    if (!private_key.ParseFromString(std::string(serialized_private_key))) {
      return crypto::tink::util::Status(
          absl::StatusCode::kInvalidArgument,
          absl::StrCat("Could not parse the passed string as proto '",
                       PrivateKeyProto().GetTypeName(), "'."));
    }
    auto validation = private_key_manager_->ValidateKey(private_key);
    if (!validation.ok()) return validation;
    auto key_data = absl::make_unique<google::crypto::tink::KeyData>();
    util::StatusOr<PublicKeyProto> public_key_result =
        private_key_manager_->GetPublicKey(private_key);
    if (!public_key_result.ok()) return public_key_result.status();
    key_data->set_type_url(public_key_type_);
    key_data->set_value(public_key_result.ValueOrDie().SerializeAsString());
    key_data->set_key_material_type(public_key_material_type_);
    return std::move(key_data);
  }

 private:
  // We create a key_factory_impl_ as a member, instead of using virtual
  // inheritance to have it as a sub class. This means we have to forward the
  // calls to NewKeyData as above, but developers do not have to know about
  // virtual inheritance.
  KeyFactoryImpl<KeyTypeManager<PrivateKeyProto, PrivateKeyFormatProto,
                                PrivatePrimitivesList>>
      key_factory_impl_;
  PrivateKeyTypeManager<PrivateKeyProto, PrivateKeyFormatProto, PublicKeyProto,
                        PrivatePrimitivesList>* private_key_manager_;
  const std::string public_key_type_;
  google::crypto::tink::KeyData::KeyMaterialType public_key_material_type_;
};

template <class Primitive, class PrivateKeyTypeManager,
          class PublicKeyTypeManager>
class PrivateKeyManagerImpl;

template <class Primitive, class PrivateKeyProto, class KeyFormatProto,
          class PublicKeyProto, class PrivatePrimitivesList,
          class PublicPrimitivesList>
class PrivateKeyManagerImpl<
    Primitive,
    PrivateKeyTypeManager<PrivateKeyProto, KeyFormatProto, PublicKeyProto,
                          PrivatePrimitivesList>,
    KeyTypeManager<PublicKeyProto, void, PublicPrimitivesList>>
    : public KeyManagerImpl<Primitive,
                            KeyTypeManager<PrivateKeyProto, KeyFormatProto,
                                           PrivatePrimitivesList>> {
 public:
  explicit PrivateKeyManagerImpl(
      PrivateKeyTypeManager<PrivateKeyProto, KeyFormatProto, PublicKeyProto,
                            PrivatePrimitivesList>* private_key_manager,
      KeyTypeManager<PublicKeyProto, void, PublicPrimitivesList>*
          public_key_manager)
      : KeyManagerImpl<Primitive,
                       KeyTypeManager<PrivateKeyProto, KeyFormatProto,
                                      PrivatePrimitivesList>>(
            private_key_manager),
        private_key_factory_(private_key_manager, public_key_manager) {}

  const PrivateKeyFactory& get_key_factory() const override {
    return private_key_factory_;
  }

 private:
  const PrivateKeyFactoryImpl<PrivateKeyProto, KeyFormatProto, PublicKeyProto,
                              PrivatePrimitivesList, PublicPrimitivesList>
      private_key_factory_;
};

// Helper function to create a KeyManager<Primitive> for a
// PrivateKeyTypeManager. Using this, all template arguments except the
// first one can be infered. Example:
//   std::unique_ptr<KeyManager<PublicKeySign>> km =
//     MakePrivateKeyManager<PublicKeySign>(internal_private_km,
//                                          internal_public_km);
//
// When creating a KeyManager like this, the passed in "private_key_manager"
// must outlive the constructed KeyManager. The passed in "public_key_manager"
// however must only be valid during construction of the KeyManager.
template <class Primitive, class PrivateKeyProto, class KeyFormatProto,
          class PublicKeyProto, class PrivatePrimitivesList,
          class PublicPrimitivesList>
std::unique_ptr<KeyManager<Primitive>> MakePrivateKeyManager(
    PrivateKeyTypeManager<PrivateKeyProto, KeyFormatProto, PublicKeyProto,
                          PrivatePrimitivesList>* private_key_manager,
    KeyTypeManager<PublicKeyProto, void, PublicPrimitivesList>*
        public_key_manager) {
  return absl::make_unique<PrivateKeyManagerImpl<
      Primitive,
      PrivateKeyTypeManager<PrivateKeyProto, KeyFormatProto, PublicKeyProto,
                            PrivatePrimitivesList>,
      KeyTypeManager<PublicKeyProto, void, PublicPrimitivesList>>>(
      private_key_manager, public_key_manager);
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_CORE_PRIVATE_KEY_MANAGER_IMPL_H_
