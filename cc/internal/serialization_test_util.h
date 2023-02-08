// Copyright 2023 Google LLC
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

#ifndef TINK_INTERNAL_SERIALIZATION_TEST_UTIL_H_
#define TINK_INTERNAL_SERIALIZATION_TEST_UTIL_H_

#include <string>

#include "tink/internal/serialization.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

constexpr absl::string_view kNoIdTypeUrl = "NoIdTypeUrl";
constexpr absl::string_view kIdTypeUrl = "IdTypeUrl";

// Generic serialization for keys or parameters.
class BaseSerialization : public Serialization {
 public:
  explicit BaseSerialization(absl::string_view object_identifier)
      : object_identifier_(object_identifier) {}

  absl::string_view ObjectIdentifier() const override {
    return object_identifier_;
  }

  bool operator==(const BaseSerialization& other) const {
    return object_identifier_ == other.object_identifier_;
  }

 private:
  std::string object_identifier_;
};

// Serialization for keys or parameters without an ID requirement.
class NoIdSerialization : public BaseSerialization {
 public:
  NoIdSerialization() : BaseSerialization(kNoIdTypeUrl) {}
};

// Serialization for parameters with an ID requirement.
class IdParamsSerialization : public BaseSerialization {
 public:
  IdParamsSerialization() : BaseSerialization(kIdTypeUrl) {}
};

// Serialization for keys with an ID requirement.
class IdKeySerialization : public BaseSerialization {
 public:
  explicit IdKeySerialization(int id)
      : BaseSerialization(kIdTypeUrl), id_(id) {}

  int GetKeyId() const { return id_; }

 private:
  int id_;
};

// Parameters without an ID requirement.
class NoIdParams : public Parameters {
 public:
  bool HasIdRequirement() const override { return false; }

  bool operator==(const Parameters& other) const override {
    return !other.HasIdRequirement();
  }
};

// Key without an ID requirement.
class NoIdKey : public Key {
 public:
  const Parameters& GetParameters() const override { return params_; }

  absl::optional<int> GetIdRequirement() const override {
    return absl::nullopt;
  }

  bool operator==(const Key& other) const override {
    return params_ == other.GetParameters() &&
           absl::nullopt == other.GetIdRequirement();
  }

 private:
  NoIdParams params_;
};

// Parameters with an ID requirement.
class IdParams : public Parameters {
 public:
  bool HasIdRequirement() const override { return true; }

  bool operator==(const Parameters& other) const override {
    return other.HasIdRequirement();
  }
};

// Key with an ID requirement.
class IdKey : public Key {
 public:
  explicit IdKey(int id) : id_(id) {}

  const Parameters& GetParameters() const override { return params_; }

  absl::optional<int> GetIdRequirement() const override { return id_; }

  bool operator==(const Key& other) const override {
    return params_ == other.GetParameters() && id_ == other.GetIdRequirement();
  }

 private:
  IdParams params_;
  int id_;
};

// Parse `serialization` into parameters without an ID requirement.
inline util::StatusOr<NoIdParams> ParseNoIdParams(
    NoIdSerialization serialization) {
  return NoIdParams();
}

// Parse `serialization` into parameters with an ID requirement.
inline util::StatusOr<IdParams> ParseIdParams(
    IdParamsSerialization serialization) {
  return IdParams();
}

// Serialize `parameters` without an ID requirement.
inline util::StatusOr<NoIdSerialization> SerializeNoIdParams(
    NoIdParams parameters) {
  return NoIdSerialization();
}

// Serialize `parameters` with an ID requirement.
inline util::StatusOr<IdParamsSerialization> SerializeIdParams(
    IdParams parameters) {
  return IdParamsSerialization();
}

// Parse `serialization` into a key without an ID requirement.
inline util::StatusOr<NoIdKey> ParseNoIdKey(NoIdSerialization serialization,
                                            SecretKeyAccessToken token) {
  return NoIdKey();
}

// Parse `serialization` into a key with an ID requirement.
inline util::StatusOr<IdKey> ParseIdKey(IdKeySerialization serialization,
                                        SecretKeyAccessToken token) {
  return IdKey(serialization.GetKeyId());
}

// Serialize `key` without an ID requirement.
inline util::StatusOr<NoIdSerialization> SerializeNoIdKey(
    NoIdKey key, SecretKeyAccessToken token) {
  return NoIdSerialization();
}

// Serialize `key` with an ID requirement.
inline util::StatusOr<IdKeySerialization> SerializeIdKey(
    IdKey key, SecretKeyAccessToken token) {
  return IdKeySerialization(key.GetIdRequirement().value());
}

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_SERIALIZATION_TEST_UTIL_H_
