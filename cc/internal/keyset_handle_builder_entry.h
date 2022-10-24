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

#ifndef TINK_INTERNAL_KEYSET_HANDLE_BUILDER_ENTRY_H_
#define TINK_INTERNAL_KEYSET_HANDLE_BUILDER_ENTRY_H_

#include <memory>
#include <utility>

#include "tink/key.h"
#include "tink/key_status.h"
#include "tink/parameters.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace internal {

enum class KeyIdStrategyEnum : int {
  kFixedId = 1,
  kRandomId = 2,
  // Added to guard from failures that may be caused by future expansions.
  kDoNotUseInsteadUseDefaultWhenWritingSwitchStatements = 20,
};

struct KeyIdStrategy {
  KeyIdStrategyEnum strategy;
  absl::optional<int> id_requirement;
};

// Internal keyset handle builder entry. The public keyset handle builder
// entry will delegate its method calls to an instance of this class.
class KeysetHandleBuilderEntry {
 public:
  KeysetHandleBuilderEntry() = default;
  virtual ~KeysetHandleBuilderEntry() = default;

  // Sets the key `status` of this entry.
  void SetStatus(KeyStatus status) { key_status_ = status; }
  // Returns key status of this entry.
  KeyStatus GetStatus() const { return key_status_; }

  // Assigns a fixed `id` when this keyset is built.
  void SetFixedId(int id);
  // Assigns an unused random id when this keyset is built.
  void SetRandomId();

  // Sets this entry as the primary key.
  void SetPrimary() { is_primary_ = true; }
  // Unsets this entry as the primary key.
  void UnsetPrimary() { is_primary_ = false; }
  // Returns whether or not this entry has been marked as a primary.
  bool IsPrimary() const { return is_primary_; }

  // Returns key id strategy.
  KeyIdStrategy GetKeyIdStrategy() { return strategy_; }
  // Returns key id strategy enum.
  KeyIdStrategyEnum GetKeyIdStrategyEnum() { return strategy_.strategy; }
  // Returns key id requirement.
  absl::optional<int> GetKeyIdRequirement() { return strategy_.id_requirement; }

  // Creates a Keyset::Key proto with the specified key `id` from either a
  // `Key` object or a `Parameters` object.
  virtual crypto::tink::util::StatusOr<google::crypto::tink::Keyset::Key>
  CreateKeysetKey(int id) = 0;

 protected:
  KeyStatus key_status_ = KeyStatus::kDisabled;

 private:
  bool is_primary_ = false;
  KeyIdStrategy strategy_ =
      KeyIdStrategy{KeyIdStrategyEnum::kRandomId, absl::nullopt};
};

// Internal keyset handle builder entry constructed from a `Key` object.
class KeyEntry : public KeysetHandleBuilderEntry {
 public:
  // Movable, but not copyable.
  KeyEntry(KeyEntry&& other) = default;
  KeyEntry& operator=(KeyEntry&& other) = default;
  KeyEntry(const KeyEntry& other) = delete;
  KeyEntry& operator=(const KeyEntry& other) = delete;

  explicit KeyEntry(std::unique_ptr<Key> key) : key_(std::move(key)) {}

  crypto::tink::util::StatusOr<google::crypto::tink::Keyset::Key>
  CreateKeysetKey(int id) override;

 private:
  std::unique_ptr<Key> key_;
};

// Internal keyset handle builder entry constructed from a `Parameters` object.
class ParametersEntry : public KeysetHandleBuilderEntry {
 public:
  // Movable, but not copyable.
  ParametersEntry(ParametersEntry&& other) = default;
  ParametersEntry& operator=(ParametersEntry&& other) = default;
  ParametersEntry(const ParametersEntry& other) = delete;
  ParametersEntry& operator=(const ParametersEntry& other) = delete;

  explicit ParametersEntry(std::unique_ptr<Parameters> parameters)
      : parameters_(std::move(parameters)) {}

  crypto::tink::util::StatusOr<google::crypto::tink::Keyset::Key>
  CreateKeysetKey(int id) override;

 private:
  std::unique_ptr<Parameters> parameters_;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_KEYSET_HANDLE_BUILDER_ENTRY_H_
