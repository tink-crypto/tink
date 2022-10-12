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

#ifndef TINK_INTERNAL_LEGACY_PROTO_KEY_H_
#define TINK_INTERNAL_LEGACY_PROTO_KEY_H_

#include <string>

#include "tink/internal/proto_key_serialization.h"
#include "tink/key.h"
#include "tink/secret_key_access_token.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

// Parameters returned by `LegacyProtoKey::GetParameters()` that cannot be used
// to create other LegacyProtoKey instances.
class UnusableLegacyProtoParameters : public Parameters {
 public:
  // Copyable and movable.
  UnusableLegacyProtoParameters(const UnusableLegacyProtoParameters& other) =
      default;
  UnusableLegacyProtoParameters& operator=(
      const UnusableLegacyProtoParameters& other) = default;
  UnusableLegacyProtoParameters(UnusableLegacyProtoParameters&& other) =
      default;
  UnusableLegacyProtoParameters& operator=(
      UnusableLegacyProtoParameters&& other) = default;

  explicit UnusableLegacyProtoParameters(
      absl::string_view type_url,
      google::crypto::tink::OutputPrefixType output_prefix_type)
      : type_url_(type_url), output_prefix_type_(output_prefix_type) {}

  bool HasIdRequirement() const override {
    return output_prefix_type_ != google::crypto::tink::OutputPrefixType::RAW;
  }

  bool operator==(const Parameters& other) const override;

 private:
  std::string type_url_;
  google::crypto::tink::OutputPrefixType output_prefix_type_;
};

// Key type for legacy proto keys.
class LegacyProtoKey : public Key {
 public:
  // Copyable and movable.
  LegacyProtoKey(const LegacyProtoKey& other) = default;
  LegacyProtoKey& operator=(const LegacyProtoKey& other) = default;
  LegacyProtoKey(LegacyProtoKey&& other) = default;
  LegacyProtoKey& operator=(LegacyProtoKey&& other) = default;

  // Creates `LegacyProtoKey` object from `serialization`.  Requires `token` if
  // the key material type is either SYMMETRIC or ASYMMETRIC_PRIVATE.
  static util::StatusOr<LegacyProtoKey> Create(
      ProtoKeySerialization serialization,
      absl::optional<SecretKeyAccessToken> token);

  const Parameters& GetParameters() const override {
    return unusable_proto_parameters_;
  }

  absl::optional<int> GetIdRequirement() const override {
    return serialization_.IdRequirement();
  }

  bool operator==(const Key& other) const override;

  // Returns `ProtoKeySerialization` pointer for this object.  Requires `token`
  // if the key material type is either SYMMETRIC or ASYMMETRIC_PRIVATE.
  util::StatusOr<const ProtoKeySerialization*> Serialization(
      absl::optional<SecretKeyAccessToken> token) const;

 private:
  explicit LegacyProtoKey(ProtoKeySerialization serialization)
      : serialization_(serialization),
        unusable_proto_parameters_(serialization.TypeUrl(),
                                   serialization.GetOutputPrefixType()) {}

  ProtoKeySerialization serialization_;
  UnusableLegacyProtoParameters unusable_proto_parameters_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_LEGACY_PROTO_KEY_H_
