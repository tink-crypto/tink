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

#ifndef TINK_INTERNAL_MUTABLE_SERIALIZATION_REGISTRY_H_
#define TINK_INTERNAL_MUTABLE_SERIALIZATION_REGISTRY_H_

#include <memory>

#include "absl/base/thread_annotations.h"
#include "absl/synchronization/mutex.h"
#include "absl/types/optional.h"
#include "tink/internal/key_parser.h"
#include "tink/internal/key_serializer.h"
#include "tink/internal/parameters_parser.h"
#include "tink/internal/parameters_serializer.h"
#include "tink/internal/serialization.h"
#include "tink/internal/serialization_registry.h"
#include "tink/key.h"
#include "tink/parameters.h"
#include "tink/secret_key_access_token.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// This class provides a global, mutable serialization registry by wrapping an
// instance of an immutable `SerializationRegistry`.  This registry will enable
// the Tink 2.0 C++ Keyset API in the near term.
class MutableSerializationRegistry {
 public:
  // Returns the global serialization registry.
  static MutableSerializationRegistry& GlobalInstance();

  // Registers parameters `parser`. Returns an error if a different parameters
  // parser with the same parser index has already been registered.
  util::Status RegisterParametersParser(ParametersParser* parser)
      ABSL_LOCKS_EXCLUDED(registry_mutex_);

  // Registers parameters `serializer`. Returns an error if a different
  // parameters serializer with the same serializer index has already been
  // registered.
  util::Status RegisterParametersSerializer(ParametersSerializer* serializer)
      ABSL_LOCKS_EXCLUDED(registry_mutex_);

  // Registers key `parser`. Returns an error if a different key parser with the
  // same parser index has already been registered.
  util::Status RegisterKeyParser(KeyParser* parser)
      ABSL_LOCKS_EXCLUDED(registry_mutex_);

  // Registers key `serializer`. Returns an error if a different key serializer
  // with the same serializer index has already been registered.
  util::Status RegisterKeySerializer(KeySerializer* serializer)
      ABSL_LOCKS_EXCLUDED(registry_mutex_);

  // Parses `serialization` into a `Parameters` instance.
  util::StatusOr<std::unique_ptr<Parameters>> ParseParameters(
      const Serialization& serialization) ABSL_LOCKS_EXCLUDED(registry_mutex_);

  // Serializes `parameters` into a `Serialization` instance.
  template <typename SerializationT>
  util::StatusOr<std::unique_ptr<Serialization>> SerializeParameters(
      const Parameters& parameters) ABSL_LOCKS_EXCLUDED(registry_mutex_) {
    absl::MutexLock lock(&registry_mutex_);
    return registry_.SerializeParameters<SerializationT>(parameters);
  }

  // Parses `serialization` into a `Key` instance.
  util::StatusOr<std::unique_ptr<Key>> ParseKey(
      const Serialization& serialization,
      absl::optional<SecretKeyAccessToken> token)
      ABSL_LOCKS_EXCLUDED(registry_mutex_);

  // Similar to `ParseKey` but falls back to legacy proto key serialization if
  // the corresponding key parser is not found.
  util::StatusOr<std::unique_ptr<Key>> ParseKeyWithLegacyFallback(
      const Serialization& serialization, SecretKeyAccessToken token);

  // Serializes `parameters` into a `Serialization` instance.
  template <typename SerializationT>
  util::StatusOr<std::unique_ptr<Serialization>> SerializeKey(
      const Key& key, absl::optional<SecretKeyAccessToken> token)
      ABSL_LOCKS_EXCLUDED(registry_mutex_) {
    absl::MutexLock lock(&registry_mutex_);
    return registry_.SerializeKey<SerializationT>(key, token);
  }

  // Resets to a new empty registry.
  void Reset() ABSL_LOCKS_EXCLUDED(registry_mutex_) {
    absl::MutexLock lock(&registry_mutex_);
    registry_ = SerializationRegistry();
  }

 private:
  mutable absl::Mutex registry_mutex_;
  SerializationRegistry registry_ ABSL_GUARDED_BY(registry_mutex_);
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_MUTABLE_SERIALIZATION_REGISTRY_H_
