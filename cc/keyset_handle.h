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

#ifndef TINK_KEYSET_HANDLE_H_
#define TINK_KEYSET_HANDLE_H_

#include <string>

#include "absl/base/attributes.h"
#include "absl/status/status.h"
#include "tink/aead.h"
#include "tink/internal/key_info.h"
#include "tink/key_manager.h"
#include "tink/keyset_reader.h"
#include "tink/keyset_writer.h"
#include "tink/primitive_set.h"
#include "tink/registry.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// KeysetHandle provides abstracted access to Keysets, to limit
// the exposure of actual protocol buffers that hold sensitive
// key material.
class KeysetHandle {
 public:
  // Creates a KeysetHandle from an encrypted keyset obtained via |reader|
  // using |master_key_aead| to decrypt the keyset.
  static crypto::tink::util::StatusOr<std::unique_ptr<KeysetHandle>> Read(
      std::unique_ptr<KeysetReader> reader, const Aead& master_key_aead);

  // Creates a KeysetHandle from an encrypted keyset obtained via |reader|
  // using |master_key_aead| to decrypt the keyset, expecting |associated_data|.
  static crypto::tink::util::StatusOr<std::unique_ptr<KeysetHandle>>
  ReadWithAssociatedData(std::unique_ptr<KeysetReader> reader,
                         const Aead& master_key_aead,
                         absl::string_view associated_data);

  // Creates a KeysetHandle from a keyset which contains no secret key material.
  // This can be used to load public keysets or envelope encryption keysets.
  static crypto::tink::util::StatusOr<std::unique_ptr<KeysetHandle>>
  ReadNoSecret(const std::string& serialized_keyset);

  // Returns a new KeysetHandle that contains a single fresh key generated
  // according to |key_template|.
  static crypto::tink::util::StatusOr<std::unique_ptr<KeysetHandle>>
  GenerateNew(const google::crypto::tink::KeyTemplate& key_template);

  // Encrypts the underlying keyset with the provided |master_key_aead|
  // and writes the resulting EncryptedKeyset to the given |writer|,
  // which must be non-null.
  crypto::tink::util::Status Write(KeysetWriter* writer,
                                   const Aead& master_key_aead) const;

  // Encrypts the underlying keyset with the provided |master_key_aead|, using
  // |associated_data|. and writes the resulting EncryptedKeyset to the given
  // |writer|, which must be non-null.
  crypto::tink::util::Status WriteWithAssociatedData(
      KeysetWriter* writer, const Aead& master_key_aead,
      absl::string_view associated_data) const;

  // Returns KeysetInfo, a "safe" Keyset that doesn't contain any actual
  // key material, thus can be used for logging or monitoring.
  google::crypto::tink::KeysetInfo GetKeysetInfo() const;

  // Writes the underlying keyset to |writer| only if the keyset does not
  // contain any secret key material.
  // This can be used to persist public keysets or envelope encryption keysets.
  // Users that need to persist cleartext keysets can use
  // |CleartextKeysetHandle|.
  crypto::tink::util::Status WriteNoSecret(KeysetWriter* writer) const;

  // Returns a new KeysetHandle that contains public keys corresponding
  // to the private keys from this handle.
  // Returns an error if this handle contains keys that are not private keys.
  crypto::tink::util::StatusOr<std::unique_ptr<KeysetHandle>>
  GetPublicKeysetHandle() const;

  // Creates a wrapped primitive corresponding to this keyset or fails with
  // a non-ok status. Uses the KeyManager and PrimitiveWrapper objects in the
  // global registry to create the primitive. This function is the most common
  // way of creating a primitive.
  template <class P>
  crypto::tink::util::StatusOr<std::unique_ptr<P>> GetPrimitive() const;

  // Creates a wrapped primitive corresponding to this keyset. Uses the given
  // KeyManager, as well as the KeyManager and PrimitiveWrapper objects in the
  // global registry to create the primitive. The given KeyManager is used for
  // keys supported by it. For those, the registry is ignored.
  template <class P>
  ABSL_DEPRECATED("Register the keymanager and use GetPrimitive")
  crypto::tink::util::StatusOr<std::unique_ptr<P>> GetPrimitive(
      const KeyManager<P>* custom_manager) const;

 private:
  // The classes below need access to get_keyset();
  friend class CleartextKeysetHandle;
  friend class KeysetManager;
  friend class RegistryImpl;

  // TestKeysetHandle::GetKeyset() provides access to get_keyset().
  friend class TestKeysetHandle;

  // Creates a handle that contains the given keyset.
  explicit KeysetHandle(google::crypto::tink::Keyset keyset);
  // Creates a handle that contains the given keyset.
  explicit KeysetHandle(std::unique_ptr<google::crypto::tink::Keyset> keyset);

  // Helper function which generates a key from a template, then adds it
  // to the keyset. TODO(tholenst): Change this to a proper member operating
  // on the internal keyset.
  static crypto::tink::util::StatusOr<uint32_t> AddToKeyset(
      const google::crypto::tink::KeyTemplate& key_template, bool as_primary,
      google::crypto::tink::Keyset* keyset);

  // Returns keyset held by this handle.
  const google::crypto::tink::Keyset& get_keyset() const;

  // Creates a set of primitives corresponding to the keys with
  // (status == ENABLED) in the keyset given in 'keyset_handle',
  // assuming all the corresponding key managers are present (keys
  // with (status != ENABLED) are skipped).
  //
  // The returned set is usually later "wrapped" into a class that
  // implements the corresponding Primitive-interface.
  template <class P>
  crypto::tink::util::StatusOr<std::unique_ptr<PrimitiveSet<P>>> GetPrimitives(
      const KeyManager<P>* custom_manager) const;

  google::crypto::tink::Keyset keyset_;
};

///////////////////////////////////////////////////////////////////////////////
// Implementation details of templated methods.

template <class P>
crypto::tink::util::StatusOr<std::unique_ptr<PrimitiveSet<P>>>
KeysetHandle::GetPrimitives(const KeyManager<P>* custom_manager) const {
  crypto::tink::util::Status status = ValidateKeyset(get_keyset());
  if (!status.ok()) return status;
  std::unique_ptr<PrimitiveSet<P>> primitives(new PrimitiveSet<P>());
  for (const google::crypto::tink::Keyset::Key& key : get_keyset().key()) {
    if (key.status() == google::crypto::tink::KeyStatusType::ENABLED) {
      std::unique_ptr<P> primitive;
      if (custom_manager != nullptr &&
          custom_manager->DoesSupport(key.key_data().type_url())) {
        auto primitive_result = custom_manager->GetPrimitive(key.key_data());
        if (!primitive_result.ok()) return primitive_result.status();
        primitive = std::move(primitive_result.value());
      } else {
        auto primitive_result = Registry::GetPrimitive<P>(key.key_data());
        if (!primitive_result.ok()) return primitive_result.status();
        primitive = std::move(primitive_result.value());
      }
      auto entry_result =
          primitives->AddPrimitive(std::move(primitive), KeyInfoFromKey(key));
      if (!entry_result.ok()) return entry_result.status();
      if (key.key_id() == get_keyset().primary_key_id()) {
        auto primary_result = primitives->set_primary(entry_result.value());
        if (!primary_result.ok()) return primary_result;
      }
    }
  }
  return std::move(primitives);
}

template <class P>
crypto::tink::util::StatusOr<std::unique_ptr<P>> KeysetHandle::GetPrimitive()
    const {
  return internal::RegistryImpl::GlobalInstance().WrapKeyset<P>(keyset_);
}

template <class P>
crypto::tink::util::StatusOr<std::unique_ptr<P>> KeysetHandle::GetPrimitive(
    const KeyManager<P>* custom_manager) const {
  if (custom_manager == nullptr) {
    return crypto::tink::util::Status(absl::StatusCode::kInvalidArgument,
                                      "custom_manager must not be null");
  }
  auto primitives_result = this->GetPrimitives<P>(custom_manager);
  if (!primitives_result.ok()) {
    return primitives_result.status();
  }
  return Registry::Wrap<P>(std::move(primitives_result.value()));
}

}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEYSET_HANDLE_H_
