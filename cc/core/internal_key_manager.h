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

#ifndef TINK_INTERNAL_KEY_MANAGER_H_
#define TINK_INTERNAL_KEY_MANAGER_H_

#include <typeindex>

#include "absl/container/flat_hash_map.h"
#include "tink/core/template_util.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

namespace internal {
// InternalKeyFactory should not be used directly: it is an implementation
// detail. The internal key factory provides the functions which are required
// if an InternalKeyManager can create new keys: ValidateKeyFormat and
// CreateKey. The special case where KeyFormatProto = void implies that the
// functions do not exist.
template <typename KeyProto, typename KeyFormatProto>
class InternalKeyFactory {
 public:
  virtual ~InternalKeyFactory() {}

  virtual crypto::tink::util::Status ValidateKeyFormat(
      const KeyFormatProto& key_format) const = 0;
  virtual crypto::tink::util::StatusOr<KeyProto> CreateKey(
      const KeyFormatProto& key_format) const = 0;
};

template <typename KeyProto>
class InternalKeyFactory<KeyProto, void> {
 public:
  virtual ~InternalKeyFactory() {}
};

}  // namespace internal

// An InternalKeyManager manages a single key proto. This includes
//  * parsing and validating keys
//  * parsing and validating key formats (in case generating keys is allowed).
//  * creating primitives.
// To implement, one should subclass InternalKeyManager with the corresponding
// KeyProto as a template parameter; KeyFormatProto should be void in case
// the key manager cannot produce keys and a protobuf otherwise.
//
// The constructor should take unique pointers to primitive factories.
template <typename KeyProto, typename KeyFormatProto = void>
class InternalKeyManager
    : public internal::InternalKeyFactory<KeyProto, KeyFormatProto> {
 public:
  // A PrimitiveFactory<Primitive> knows how to create instances of the
  // Primitive.
  template <typename Primitive>
  class PrimitiveFactory {
   public:
    // Used for template deduction.
    using UnderlyingPrimitive = Primitive;

    virtual ~PrimitiveFactory() {}
    virtual crypto::tink::util::StatusOr<std::unique_ptr<Primitive>> Create(
        const KeyProto& key) const = 0;
  };

  // Creates a new InternalKeyManager. The parameter(s) primitives must be some
  // number of unique_ptr<PrimitiveFactory<P>> types.
  template <typename... PrimitiveFactories>
  explicit InternalKeyManager(
      std::unique_ptr<PrimitiveFactories>... primitives) {
    AddAllPrimitives<typename PrimitiveFactories::UnderlyingPrimitive...>(
        std::move(primitives)...);
  }

  // Returns the type_url identifying the key type handled by this manager.
  virtual const std::string& get_key_type() const = 0;
  // Returns the version of this key manager.
  virtual uint32_t get_version() const = 0;

  // Returns the key material type for this key type.
  virtual google::crypto::tink::KeyData::KeyMaterialType key_material_type()
      const = 0;

  // Validates the key. Returns util::OkStatus() if the key is valid,
  // and an invalid argument error otherwise.
  virtual util::Status ValidateKey(const KeyProto& key) const = 0;

  // Creates a new primitive using one of the primitive factories passed in at
  // construction time.
  template <typename Primitive>
  crypto::tink::util::StatusOr<std::unique_ptr<Primitive>> GetPrimitive(
      const KeyProto& key) const {
    auto iter = primitive_factories_.find(std::type_index(typeid(Primitive)));
    if (iter == primitive_factories_.end()) {
      return crypto::tink::util::Status(
          util::error::INVALID_ARGUMENT,
          absl::StrCat("No PrimitiveFactory was registered for type ",
                       typeid(Primitive).name()));
    }
    return static_cast<PrimitiveFactory<Primitive>*>(iter->second.get())
        ->Create(key);
  }

 private:
  // Actual helper function to put the primitive factories into the hash map
  // primitive_factories_. Only enabled if the primitives in the given
  // Primitives template parameters are distinct.
  template <typename... Primitives>
  typename std::enable_if<
      !crypto::tink::internal::HasDuplicates<Primitives...>::value>::type
  AddAllPrimitives(
      std::unique_ptr<PrimitiveFactory<Primitives>>... primitives) {
    // https://stackoverflow.com/questions/17339789/how-to-call-a-function-on-all-variadic-template-args
    ABSL_ATTRIBUTE_UNUSED
    int unused[] = {(AddPrimitive(std::move(primitives)), 0)...};
  }

  // Helper function which adds a single primivie.
  template <typename Primitive>
  void AddPrimitive(std::unique_ptr<PrimitiveFactory<Primitive>> primitive) {
    primitive_factories_.emplace(std::type_index(typeid(Primitive)),
                                 std::move(primitive));
  }

  // Replacement helper function for AddAllPrimitives which always fails with
  // an error message when compiling. Only enabled if at least one primitive
  // appears at least twice.
  template <typename... Primitives>
  typename std::enable_if<
      crypto::tink::internal::HasDuplicates<Primitives...>::value>::type
  AddAllPrimitives(
      std::unique_ptr<PrimitiveFactory<Primitives>>... primitives) {
    static_assert(sizeof(KeyProto) < 0,
                  "The list of arguments to InternalKeyManager contains two "
                  "PrimitiveFactory objects for the same primitive.");
  }

  // We use a shared_ptr here because shared_ptr<void> is valid (as opposed to
  // unique_ptr<void>, where we would have to add a custom deleter with extra
  // work).
  absl::flat_hash_map<std::type_index, std::shared_ptr<void>>
      primitive_factories_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_KEY_MANAGER_H_
