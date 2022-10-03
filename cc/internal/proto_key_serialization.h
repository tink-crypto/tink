// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_INTERNAL_PROTO_KEY_SERIALIZATION_H_
#define TINK_INTERNAL_PROTO_KEY_SERIALIZATION_H_

#include <string>
#include <utility>

#include "tink/internal/serialization.h"
#include "tink/util/statusor.h"
#include "tink/restricted_data.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

// Represents a `Key` object serialized with binary protocol buffer
// serialization.
class ProtoKeySerialization : public Serialization {
 public:
  // Creates a `ProtoKeySerialization` object from individual components.
  static util::StatusOr<ProtoKeySerialization> Create(
      absl::string_view type_url, RestrictedData serialized_key,
      google::crypto::tink::KeyData::KeyMaterialType key_material_type,
      google::crypto::tink::OutputPrefixType output_prefix_type,
      absl::optional<int> id_requirement);

  // Returned value is only valid for the lifetime of this object.
  absl::string_view TypeUrl() const { return type_url_; }

  // Returned value is only valid for the lifetime of this object.
  absl::string_view ObjectIdentifier() const override {
    return object_identifier_;
  }

  // Returned value is only valid for the lifetime of this object.
  RestrictedData SerializedKeyProto() const { return serialized_key_; }

  google::crypto::tink::KeyData::KeyMaterialType KeyMaterialType() const {
    return key_material_type_;
  }

  google::crypto::tink::OutputPrefixType GetOutputPrefixType() const {
    return output_prefix_type_;
  }

  absl::optional<int> IdRequirement() const { return id_requirement_; }

 private:
  friend class ProtoKeySerializationTest;

  ProtoKeySerialization(
      absl::string_view type_url, absl::string_view object_identifier,
      RestrictedData serialized_key,
      google::crypto::tink::KeyData::KeyMaterialType key_material_type,
      google::crypto::tink::OutputPrefixType output_prefix_type,
      absl::optional<int> id_requirement)
      : type_url_(type_url),
        object_identifier_(object_identifier),
        serialized_key_(std::move(serialized_key)),
        key_material_type_(key_material_type),
        output_prefix_type_(output_prefix_type),
        id_requirement_(id_requirement) {}

  // Returns `true` if this `ProtoKeySerialization` object is equal to
  // `other` (with the possibility of false negatives due to lack of
  // determinism during serialization).  Should only be used temporarily by the
  // to-be-implemented `LegacyKeyParameters` class.
  bool EqualsWithPotentialFalseNegatives(
      const ProtoKeySerialization& other) const;

  std::string type_url_;
  std::string object_identifier_;
  RestrictedData serialized_key_;
  google::crypto::tink::KeyData::KeyMaterialType key_material_type_;
  google::crypto::tink::OutputPrefixType output_prefix_type_;
  absl::optional<int> id_requirement_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_PROTO_KEY_SERIALIZATION_H_
