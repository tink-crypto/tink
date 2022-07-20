// Copyright 2022 Google LLC
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
#ifndef TINK_MONITORING_MONITORING_H_
#define TINK_MONITORING_MONITORING_H_

#include <cstdint>
#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Immutable representation of a KeySet in a certain point in time for the
// purpose of monitoring operations involving cryptographic keys.
class MonitoringKeySetInfo {
 public:
  // Description about each entry of the KeySet.
  class Entry {
   public:
    // Enum representation of KeyStatusType in tink/proto/tink.proto. Using an
    // enum class prevents unintentional implicit conversions.
    enum class KeyStatus : int {
      kEnabled = 1,    // Can be used for cryptographic operations.
      kDisabled = 2,   // Cannot be used (but can become kEnabled again).
      kDestroyed = 3,  // Key data does not exist in this Keyset any more.
      // Added to guard from failures that may be caused by future expansions.
      kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
    };

    // Constructs a new KeySet entry with a given `status`, `key_id` and key
    // format `key_format_as_string`.
    Entry(KeyStatus status, uint32_t key_id,
          absl::string_view key_format_as_string)
        : status_(status),
          key_id_(key_id),
          key_format_as_string_(key_format_as_string) {}

    // Returns the status of this entry.
    KeyStatus GetStatus() const { return status_; }
    // Returns the ID of the entry within the keyset.
    uint32_t GetKeyId() const { return key_id_; }
    // Returns the key format in a serialized form.
    //
    // *WARNING* the actual content of `key_format_as_string_` is considered
    // unstable and might change in future versions of Tink. A user should not
    // rely on a specific representation of the key_format.
    std::string GetKeyFormatAsString() const { return key_format_as_string_; }

   private:
    const KeyStatus status_;
    // Identifies a key within a keyset.
    const uint32_t key_id_;
    // This field stores information about the key format.
    const std::string key_format_as_string_;
  };

  // Constructs a MonitoringKeySetInfo object with the given
  // `keyset_annotations`, `keyset_entries` and primary key ID `primary_key_id`.
  MonitoringKeySetInfo(
      const absl::flat_hash_map<std::string, std::string>& keyset_annotations,
      const std::vector<Entry>& keyset_entries, uint32_t primary_key_id)
      : keyset_annotations_(keyset_annotations),
        keyset_entries_(keyset_entries),
        primary_key_id_(primary_key_id) {}

  // Returns a const reference to the annotations of this keyset.
  const absl::flat_hash_map<std::string, std::string>& GetAnnotations() const {
    return keyset_annotations_;
  }
  // Returns a const reference to the array of entries for this keyset.
  const std::vector<Entry>& GetEntries() const { return keyset_entries_; }
  // Returns the ID of the primary key in this keyset.
  uint32_t GetPrimaryKeyId() const { return primary_key_id_; }

 private:
  // Annotations of this keyset in the form 'key' -> 'value'.
  const absl::flat_hash_map<std::string, std::string> keyset_annotations_;
  const std::vector<Entry> keyset_entries_;
  const uint32_t primary_key_id_;
};

// Defines a context for monitoring events, wich includes the primitive and API
// used, and info on the keyset.
class MonitoringContext {
 public:
  // Construct a new context for the given `primitive`, `api_function` and
  // `keyset_info`.
  MonitoringContext(absl::string_view primitive, absl::string_view api_function,
                    const MonitoringKeySetInfo& keyset_info)
      : primitive_(primitive),
        api_function_(api_function),
        keyset_info_(keyset_info) {}

  // Returns the primitive.
  std::string GetPrimitive() const { return primitive_; }
  // Returns the API function.
  std::string GetApi() const { return api_function_; }
  // Returns a constant reference to the keyset info.
  const MonitoringKeySetInfo& GetKeySetInfo() const { return keyset_info_; }

 private:
  const std::string primitive_;
  const std::string api_function_;
  const MonitoringKeySetInfo keyset_info_;
};

// Interface for a monitoring client which can be registered with Tink. A
// monitoring client getis informed by Tink about certain events happening
// during cryptographic operations.
class MonitoringClient {
 public:
  virtual ~MonitoringClient() = default;
  // Logs a successful use of `key_id` on an input of `num_bytes_as_input`. Tink
  // primitive wrappers call this method when they successfully used a key to
  // carry out a primitive method, e.g. Aead::Encrypt(). As a consequence,
  // subclasses of MonitoringClient should be mindful on the amount of work
  // performed by this method, as this will be called on each cryptographic
  // operation. Implementations of MonitoringClient are responsible to add
  // context to identify, e.g., the primitive and the API function.
  virtual void Log(uint32_t key_id, int64_t num_bytes_as_input) = 0;

  // Logs a failure. Tink calls this method when a cryptographic operation
  // failed, e.g. no key could be found to decrypt a ciphertext. In this
  // case the failure is not associated with a specific key, therefore this
  // method has no arguments. The MonitoringClient implementation is responsible
  // to add context to identify where the failure comes from.
  virtual void LogFailure() = 0;
};

// Interface for a factory class that creates monitoring clients.
class MonitoringClientFactory {
 public:
  virtual ~MonitoringClientFactory() = default;
  // Create a new monitoring client that logs events related to the given
  // `context`.
  virtual crypto::tink::util::StatusOr<std::unique_ptr<MonitoringClient>> New(
      const MonitoringContext& context) = 0;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_MONITORING_MONITORING_H_
