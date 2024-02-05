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

#include "tink/keyset_handle_builder.h"

#include <iostream>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "tink/key_status.h"
#include "tink/keyset_handle.h"
#include "tink/subtle/random.h"
#include "tink/util/secret_proto.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::google::crypto::tink::Keyset;

void SetBuilderEntryAttributes(KeyStatus status, bool is_primary,
                               absl::optional<int> id,
                               KeysetHandleBuilder::Entry* entry) {
  entry->SetStatus(status);
  if (is_primary) {
    entry->SetPrimary();
  } else {
    entry->UnsetPrimary();
  }
  if (id.has_value()) {
    entry->SetFixedId(*id);
  } else {
    entry->SetRandomId();
  }
}

}  // namespace

KeysetHandleBuilder::KeysetHandleBuilder(const KeysetHandle& handle) {
  for (int i = 0; i < handle.size(); ++i) {
    KeysetHandle::Entry entry = handle[i];
    KeysetHandleBuilder::Entry builder_entry =
        KeysetHandleBuilder::Entry::CreateFromKey(
            std::move(entry.key_), entry.GetStatus(), entry.IsPrimary());
    AddEntry(std::move(builder_entry));
  }
}

KeysetHandleBuilder::Entry KeysetHandleBuilder::Entry::CreateFromKey(
    std::shared_ptr<const Key> key, KeyStatus status, bool is_primary) {
  absl::optional<int> id_requirement = key->GetIdRequirement();
  auto imported_entry = absl::make_unique<internal::KeyEntry>(std::move(key));
  KeysetHandleBuilder::Entry entry(std::move(imported_entry));
  SetBuilderEntryAttributes(status, is_primary, id_requirement, &entry);
  return entry;
}

KeysetHandleBuilder::Entry KeysetHandleBuilder::Entry::CreateFromParams(
    std::shared_ptr<const Parameters> parameters, KeyStatus status,
    bool is_primary, absl::optional<int> id) {
  auto generated_entry =
      absl::make_unique<internal::ParametersEntry>(std::move(parameters));
  KeysetHandleBuilder::Entry entry(std::move(generated_entry));
  SetBuilderEntryAttributes(status, is_primary, id, &entry);
  return entry;
}

util::StatusOr<int> KeysetHandleBuilder::NextIdFromKeyIdStrategy(
    internal::KeyIdStrategy strategy, const std::set<int>& ids_so_far) {
  if (strategy.strategy == internal::KeyIdStrategyEnum::kFixedId) {
    if (!strategy.id_requirement.has_value()) {
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "Missing fixed id with fixed id strategy.");
    }
    return *strategy.id_requirement;
  }
  if (strategy.strategy == internal::KeyIdStrategyEnum::kRandomId) {
    int id = 0;
    while (id == 0 || ids_so_far.find(id) != ids_so_far.end()) {
      id = subtle::Random::GetRandomUInt32();
    }
    return id;
  }
  return util::Status(absl::StatusCode::kInvalidArgument,
                      "Invalid key id strategy.");
}

void KeysetHandleBuilder::ClearPrimary() {
  for (KeysetHandleBuilder::Entry& entry : entries_) {
    entry.UnsetPrimary();
  }
}

KeysetHandleBuilder& KeysetHandleBuilder::AddEntry(
    KeysetHandleBuilder::Entry entry) {
  CHECK(!entry.added_to_builder_)
      << "Keyset handle builder entry already added to a builder.";
  entry.added_to_builder_ = true;
  if (entry.IsPrimary()) {
    ClearPrimary();
  }
  entries_.push_back(std::move(entry));
  return *this;
}

KeysetHandleBuilder& KeysetHandleBuilder::RemoveEntry(int index) {
  CHECK(index >= 0 && index < entries_.size())
      << "Keyset handle builder entry removal index out of range.";
  entries_.erase(entries_.begin() + index);
  return *this;
}

util::Status KeysetHandleBuilder::CheckIdAssignments() {
  // We only want random id entries after fixed id entries. Otherwise, we might
  // randomly pick an id that is later specified as a fixed id.
  for (int i = 0; i < entries_.size() - 1; ++i) {
    if (entries_[i].HasRandomId() && !entries_[i + 1].HasRandomId()) {
      return util::Status(absl::StatusCode::kFailedPrecondition,
                          "Entries with random ids may only be followed "
                          "by other entries with random ids.");
    }
  }
  return util::OkStatus();
}

util::StatusOr<KeysetHandle> KeysetHandleBuilder::Build() {
  if (build_called_) {
      return util::Status(
          absl::StatusCode::kFailedPrecondition,
          "KeysetHandleBuilder::Build may only be called once");
  }
  build_called_ = true;
  util::SecretProto<Keyset> keyset;
  absl::optional<int> primary_id = absl::nullopt;

  util::Status assigned_ids_status = CheckIdAssignments();
  if (!assigned_ids_status.ok()) return assigned_ids_status;

  std::set<int> ids_so_far;
  for (KeysetHandleBuilder::Entry& entry : entries_) {
    util::StatusOr<int> id =
        NextIdFromKeyIdStrategy(entry.GetKeyIdStrategy(), ids_so_far);
    if (!id.ok()) return id.status();

    if (ids_so_far.find(*id) != ids_so_far.end()) {
      return util::Status(
          absl::StatusCode::kAlreadyExists,
          absl::StrFormat("Next id %d is already used in the keyset.", *id));
    }
    ids_so_far.insert(*id);

    util::StatusOr<util::SecretProto<Keyset::Key>> key =
        entry.CreateKeysetKey(*id);
    if (!key.ok()) return key.status();

    *keyset->add_key() = **key;
    if (entry.IsPrimary()) {
      if (primary_id.has_value()) {
        return util::Status(
            absl::StatusCode::kInternal,
            "Primary is already set in this keyset (should never happen since "
            "primary is cleared when a new primary is added).");
      }
      primary_id = *id;
    }
  }

  if (!primary_id.has_value()) {
    return util::Status(absl::StatusCode::kFailedPrecondition,
                        "No primary set in this keyset.");
  }
  keyset->set_primary_key_id(*primary_id);
  util::StatusOr<std::vector<std::shared_ptr<const KeysetHandle::Entry>>>
      entries = KeysetHandle::GetEntriesFromKeyset(*keyset);
  return KeysetHandle(std::move(keyset), *std::move(entries));
}

}  // namespace tink
}  // namespace crypto
