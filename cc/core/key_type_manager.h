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

#ifndef TINK_CORE_KEY_TYPE_MANAGER_H_
#define TINK_CORE_KEY_TYPE_MANAGER_H_

#include <string>
#include <tuple>
#include <typeinfo>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "tink/core/template_util.h"
#include "tink/input_stream.h"
#include "tink/internal/fips_utils.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

namespace internal {
// InternalKeyFactory should not be used directly: it is an implementation
// detail. The internal key factory provides the functions which are required
// if a KeyTypeManager can create new keys: ValidateKeyFormat and
// CreateKey. The special case where KeyFormatProto = void implies that the
// functions do not exist.
template <typename KeyProto, typename KeyFormatProto>
class InternalKeyFactory {
 public:
  virtual ~InternalKeyFactory() {}

  // Validates a key format proto.  KeyFormatProtos
  // on which this function returns a non-ok status will not be passed to
  // CreateKey or DeriveKey.
  virtual crypto::tink::util::Status ValidateKeyFormat(
      const KeyFormatProto& key_format) const = 0;
  // Creates a new key. This is expected to be randomized.
  virtual crypto::tink::util::StatusOr<KeyProto> CreateKey(
      const KeyFormatProto& key_format) const = 0;
  // Creates a new key. Only needs to be overridden if it should be possible to
  // derive keys of this type. This must be deterministic. Furthermore, in order
  // to support long term usability of old keys, the KeyFormatProto should be
  // versioned.
  virtual crypto::tink::util::StatusOr<KeyProto> DeriveKey(
      const KeyFormatProto& key_format, InputStream* input_stream) const {
    return crypto::tink::util::Status(
        absl::StatusCode::kUnimplemented,
        "Deriving key not implemented for this key type.");
  }
};

// Template specialization for when KeyFormatProto = void. The compiler will
// pick the most specialized template when compiling.
template <typename KeyProto>
class InternalKeyFactory<KeyProto, void> {
 public:
  virtual ~InternalKeyFactory() {}
};

}  // namespace internal

// We declare a KeyTypeManager without giving an implementation. We then
// provide a specialization only for the case where PrimitivesList is a
// List with multiple interfaces primitives. This allows to ensure
// that such is always the case.
template <typename KeyProto, typename KeyFormatProto, typename PrimitivesList>
class KeyTypeManager;

// A KeyTypeManager manages a single key proto. This includes
//  * parsing and validating keys
//  * parsing and validating key formats (in case generating keys is allowed).
//  * creating primitives.
// To implement, one should subclass KeyTypeManager with the corresponding
// KeyProto as a template parameter; KeyFormatProto should be void in case
// the key manager cannot produce keys and a protobuf otherwise.
//
// The constructor should take unique pointers to primitive factories.
//
// KeyTypeManager uses templates for KeyProto, KeyFormatProto and a list of
// Primitives which have to be provided as a List.
template <typename KeyProtoParam, typename KeyFormatProtoParam,
          typename... Primitives>
class KeyTypeManager<KeyProtoParam, KeyFormatProtoParam, List<Primitives...>>
    : public internal::InternalKeyFactory<KeyProtoParam, KeyFormatProtoParam> {
 public:
  static_assert(
      !crypto::tink::internal::HasDuplicates<Primitives...>::value,
      "List or primitives contains a duplicate, which is not allowed.");
  // The types used in this key type manager; these can be useful when writing
  // templated code.
  using KeyProto = KeyProtoParam;
  using KeyFormatProto = KeyFormatProtoParam;
  using PrimitiveList = List<Primitives...>;

  // A PrimitiveFactory<Primitive> knows how to create instances of the
  // Primitive.
  template <typename Primitive>
  class PrimitiveFactory {
   public:
    virtual ~PrimitiveFactory() {}
    virtual crypto::tink::util::StatusOr<std::unique_ptr<Primitive>> Create(
        const KeyProto& key) const = 0;
  };

  // Creates a new KeyTypeManager. The parameter(s) primitives must be some
  // number of unique_ptr<PrimitiveFactory<P>> types.
  explicit KeyTypeManager(
      std::unique_ptr<PrimitiveFactory<Primitives>>... primitives)
      : primitive_factories_{std::move(primitives)...} {}

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
  util::StatusOr<std::unique_ptr<Primitive>> GetPrimitive(
      const KeyProto& key) const {
    return GetPrimitiveImpl<Primitive>(key);
  }

  // Returns the FIPS compatibility of this KeyTypeManager.
  virtual internal::FipsCompatibility FipsStatus() const {
    return internal::FipsCompatibility::kNotFips;
  }

 private:
  // TODO(C++17) replace with `constexpr if` after migration
  template <typename Primitive>
  typename std::enable_if<
      !internal::OccursInTuple<Primitive, std::tuple<Primitives...>>::value,
      util::StatusOr<std::unique_ptr<Primitive>>>::type
  GetPrimitiveImpl(const KeyProto& key) const {
    return util::Status(
        absl::StatusCode::kInvalidArgument,
        absl::StrCat("No PrimitiveFactory was registered for type ",
                     typeid(Primitive).name()));
  }
  template <typename Primitive>
  typename std::enable_if<
      internal::OccursInTuple<Primitive, std::tuple<Primitives...>>::value,
      util::StatusOr<std::unique_ptr<Primitive>>>::type
  GetPrimitiveImpl(const KeyProto& key) const {
    // TODO(C++14) replace with std::get<T> after migration
    constexpr size_t index =
        internal::IndexOf<Primitive, List<Primitives...>>::value;
    return std::get<index>(primitive_factories_)->Create(key);
  }

  std::tuple<std::unique_ptr<PrimitiveFactory<Primitives>>...>
      primitive_factories_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_CORE_KEY_TYPE_MANAGER_H_
