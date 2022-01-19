// Copyright 2017 Google Inc.
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

#include "tink/keyset_manager.h"

#include <random>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_reader.h"
#include "tink/registry.h"
#include "tink/util/enums.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;
using google::crypto::tink::KeyTemplate;
using crypto::tink::util::Enums;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;

// static
StatusOr<std::unique_ptr<KeysetManager>> KeysetManager::New(
    const KeyTemplate& key_template) {
  auto manager = absl::make_unique<KeysetManager>();
  auto rotate_result = manager->Rotate(key_template);
  if (!rotate_result.ok()) return rotate_result.status();
  return std::move(manager);
}

// static
StatusOr<std::unique_ptr<KeysetManager>> KeysetManager::New(
    const KeysetHandle& keyset_handle) {
  auto manager = absl::make_unique<KeysetManager>();
  absl::MutexLock lock(&manager->keyset_mutex_);
  manager->keyset_ = keyset_handle.get_keyset();
  return std::move(manager);
}

std::unique_ptr<KeysetHandle> KeysetManager::GetKeysetHandle() {
  absl::MutexLock lock(&keyset_mutex_);
  std::unique_ptr<Keyset> keyset_copy(new Keyset(keyset_));
  std::unique_ptr<KeysetHandle> handle(
      new KeysetHandle(std::move(keyset_copy)));
  return handle;
}

StatusOr<uint32_t> KeysetManager::Add(const KeyTemplate& key_template) {
  return Add(key_template, false);
}

crypto::tink::util::StatusOr<uint32_t> KeysetManager::Add(
    const google::crypto::tink::KeyTemplate& key_template, bool as_primary) {
  absl::MutexLock lock(&keyset_mutex_);
  return KeysetHandle::AddToKeyset(key_template, as_primary, &keyset_);
}

StatusOr<uint32_t> KeysetManager::Rotate(const KeyTemplate& key_template) {
  return Add(key_template, true);
}


Status KeysetManager::Enable(uint32_t key_id) {
  absl::MutexLock lock(&keyset_mutex_);
  for (auto& key : *(keyset_.mutable_key())) {
    if (key.key_id() == key_id) {
      if (key.status() != KeyStatusType::DISABLED &&
          key.status() != KeyStatusType::ENABLED) {
        return ToStatusF(absl::StatusCode::kInvalidArgument,
                         "Cannot enable key with key_id %u and status %s.",
                         key_id, Enums::KeyStatusName(key.status()));
      }
      key.set_status(KeyStatusType::ENABLED);
      return util::OkStatus();
    }
  }
  return ToStatusF(absl::StatusCode::kNotFound,
                   "No key with key_id %u found in the keyset.", key_id);
}

Status KeysetManager::Disable(uint32_t key_id) {
  absl::MutexLock lock(&keyset_mutex_);
  if (keyset_.primary_key_id() == key_id) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "Cannot disable primary key (key_id %u).", key_id);
  }
  for (auto& key : *(keyset_.mutable_key())) {
    if (key.key_id() == key_id) {
      if (key.status() != KeyStatusType::DISABLED &&
          key.status() != KeyStatusType::ENABLED) {
        return ToStatusF(absl::StatusCode::kInvalidArgument,
                         "Cannot disable key with key_id %u and status %s.",
                         key_id, Enums::KeyStatusName(key.status()));
      }
      key.set_status(KeyStatusType::DISABLED);
      return util::OkStatus();
    }
  }
  return ToStatusF(absl::StatusCode::kNotFound,
                   "No key with key_id %u found in the keyset.", key_id);
}

Status KeysetManager::Delete(uint32_t key_id) {
  absl::MutexLock lock(&keyset_mutex_);
  if (keyset_.primary_key_id() == key_id) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "Cannot delete primary key (key_id %u).", key_id);
  }
  auto key_field = keyset_.mutable_key();
  for (auto key_iter = key_field->begin();
       key_iter != key_field->end();
       key_iter++) {
    auto key = *key_iter;
    if (key.key_id() == key_id) {
      keyset_.mutable_key()->erase(key_iter);
      return util::OkStatus();
    }
  }
  return ToStatusF(absl::StatusCode::kNotFound,
                   "No key with key_id %u found in the keyset.", key_id);
}

Status KeysetManager::Destroy(uint32_t key_id) {
  absl::MutexLock lock(&keyset_mutex_);
  if (keyset_.primary_key_id() == key_id) {
    return ToStatusF(absl::StatusCode::kInvalidArgument,
                     "Cannot destroy primary key (key_id %u).", key_id);
  }
  for (auto& key : *(keyset_.mutable_key())) {
    if (key.key_id() == key_id) {
      if (key.status() != KeyStatusType::DISABLED &&
          key.status() != KeyStatusType::DESTROYED &&
          key.status() != KeyStatusType::ENABLED) {
        return ToStatusF(absl::StatusCode::kInvalidArgument,
                         "Cannot destroy key with key_id %u and status %s.",
                         key_id, Enums::KeyStatusName(key.status()));
      }
      key.clear_key_data();
      key.set_status(KeyStatusType::DESTROYED);
      return util::OkStatus();
    }
  }
  return ToStatusF(absl::StatusCode::kNotFound,
                   "No key with key_id %u found in the keyset.", key_id);
}

Status KeysetManager::SetPrimary(uint32_t key_id) {
  absl::MutexLock lock(&keyset_mutex_);
  for (auto& key : keyset_.key()) {
    if (key.key_id() == key_id) {
      if (key.status() != KeyStatusType::ENABLED) {
        return ToStatusF(absl::StatusCode::kInvalidArgument,
                         "The candidate for the primary key must be ENABLED"
                         " (key_id %u).",
                         key_id);
      }
      keyset_.set_primary_key_id(key_id);
      return util::OkStatus();
    }
  }
  return ToStatusF(absl::StatusCode::kNotFound,
                   "No key with key_id %u found in the keyset.", key_id);
}


int KeysetManager::KeyCount() const {
  absl::MutexLock lock(&keyset_mutex_);
  return keyset_.key_size();
}

}  // namespace tink
}  // namespace crypto
