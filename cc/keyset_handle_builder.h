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

#ifndef TINK_KEYSET_HANDLE_BUILDER_H_
#define TINK_KEYSET_HANDLE_BUILDER_H_

#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "absl/types/optional.h"
#include "tink/internal/keyset_handle_builder_entry.h"
#include "tink/key.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/parameters.h"
#include "tink/util/secret_proto.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// Creates new `KeysetHandle` objects.
class KeysetHandleBuilder {
 public:
  // Movable, but not copyable.
  KeysetHandleBuilder(KeysetHandleBuilder&& other) = default;
  KeysetHandleBuilder& operator=(KeysetHandleBuilder&& other) = default;
  KeysetHandleBuilder(const KeysetHandleBuilder& other) = delete;
  KeysetHandleBuilder& operator=(const KeysetHandleBuilder& other) = delete;

  // Creates initially empty keyset handle builder.
  KeysetHandleBuilder() = default;
  // Creates keyset handle builder by initially moving keys from `handle`.
  explicit KeysetHandleBuilder(const KeysetHandle& handle);

  // Represents a single entry in a `KeysetHandleBuilder`.
  class Entry {
   public:
    // Movable, but not copyable.
    Entry(Entry&& other) = default;
    Entry& operator=(Entry&& other) = default;
    Entry(const Entry& other) = delete;
    Entry& operator=(const Entry& other) = delete;

    // Creates new KeysetHandleBuilder::Entry from a given `key`. Also, sets
    // key `status` and whether or not the key `is_primary`.
    static Entry CreateFromKey(std::shared_ptr<const Key> key, KeyStatus status,
                               bool is_primary);

    template <typename CopyableKey>
    inline static Entry CreateFromCopyableKey(CopyableKey key, KeyStatus status,
                                              bool is_primary) {
      auto copyable_key = absl::make_unique<CopyableKey>(std::move(key));
      return CreateFromKey(std::move(copyable_key), status, is_primary);
    }

    // Creates new KeysetHandleBuilder::Entry from given `parameters`. Also,
    // sets key `status` and whether or not the key `is_primary`. If `id`
    // does not have a value, then the key will be assigned a random id.
    static Entry CreateFromParams(std::shared_ptr<const Parameters> parameters,
                                  KeyStatus status, bool is_primary,
                                  absl::optional<int> id = absl::nullopt);

    template <typename CopyableParameters>
    inline static Entry CreateFromCopyableParams(
        CopyableParameters parameters, KeyStatus status, bool is_primary,
        absl::optional<int> id = absl::nullopt) {
      auto copyable_params =
          absl::make_unique<CopyableParameters>(std::move(parameters));
      return CreateFromParams(std::move(copyable_params), status, is_primary,
                              id);
    }

    // Sets the key status of this entry.
    void SetStatus(KeyStatus status) { entry_->SetStatus(status); }
    // Returns key status of this entry.
    KeyStatus GetStatus() const { return entry_->GetStatus(); }

    // Assigns a fixed id when this keyset is built.
    void SetFixedId(int id) { entry_->SetFixedId(id); }
    // Assigns an unused random id when this keyset is built.
    void SetRandomId() { entry_->SetRandomId(); }

    // Sets this entry as the primary key.
    void SetPrimary() { entry_->SetPrimary(); }
    // Unsets this entry as the primary key.
    void UnsetPrimary() { entry_->UnsetPrimary(); }
    // Returns whether or not this entry has been marked as a primary.
    bool IsPrimary() const { return entry_->IsPrimary(); }

   private:
    friend class KeysetHandleBuilder;

    explicit Entry(std::unique_ptr<internal::KeysetHandleBuilderEntry> entry)
        : entry_(std::move(entry)) {}

    // Returns whether or not this entry has a randomly assigned id.
    bool HasRandomId() {
      return entry_->GetKeyIdStrategyEnum() ==
             internal::KeyIdStrategyEnum::kRandomId;
    }

    internal::KeyIdStrategy GetKeyIdStrategy() {
      return entry_->GetKeyIdStrategy();
    }

    crypto::tink::util::StatusOr<
        crypto::tink::util::SecretProto<google::crypto::tink::Keyset::Key>>
    CreateKeysetKey(int id) {
      return entry_->CreateKeysetKey(id);
    }

    std::unique_ptr<internal::KeysetHandleBuilderEntry> entry_;
    bool added_to_builder_ = false;
  };

  // Adds an `entry` to the keyset builder. Crashes if `entry` has already been
  // added to a keyset handle builder.
  KeysetHandleBuilder& AddEntry(KeysetHandleBuilder::Entry entry);
  // Removes an entry at `index` from keyset builder.
  KeysetHandleBuilder& RemoveEntry(int index);

  // Returns the number of Entry objects in this keyset builder.
  int size() const { return entries_.size(); }

  // Returns entry from keyset builder at `index`.
  KeysetHandleBuilder::Entry& operator[](int index) { return entries_[index]; }

  // Creates a new `KeysetHandle` object.
  //
  // Note: Since KeysetHandleBuilder::Entry objects might have randomly
  // generated IDs, Build() can only be called once on a single
  // KeysetHandleBuilder object.  Otherwise, the KeysetHandleBuilder::Entry
  // IDs would randomly change for each call to Build(), which would result
  // in incompatible keysets.
  crypto::tink::util::StatusOr<KeysetHandle> Build();

 private:
  // Select the next key id based on the given strategy.
  crypto::tink::util::StatusOr<int> NextIdFromKeyIdStrategy(
      internal::KeyIdStrategy strategy, const std::set<int>& ids_so_far);

  // Unset primary flag on all entries.
  void ClearPrimary();

  // Verify that entries with fixed IDs do not follow entries with random IDs.
  crypto::tink::util::Status CheckIdAssignments();

  std::vector<KeysetHandleBuilder::Entry> entries_;

  bool build_called_ = false;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEYSET_HANDLE_BUILDER_H_
