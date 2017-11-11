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

#include "cc/keyset_manager.h"

#include <inttypes.h>
#include <random>

#include "cc/keyset_handle.h"
#include "cc/keyset_reader.h"
#include "cc/registry.h"
#include "cc/util/errors.h"
#include "cc/util/ptr_util.h"
#include "proto/tink.pb.h"

using google::crypto::tink::Keyset;
using google::crypto::tink::KeyStatusType;
using google::crypto::tink::KeyTemplate;
using crypto::tink::util::Status;
using crypto::tink::util::StatusOr;

namespace crypto {
namespace tink {

uint32_t NewKeyId() {
  std::random_device rd;
  std::minstd_rand0 gen(rd());
  std::uniform_int_distribution<uint32_t> dist;
  return dist(gen);
}

// static
StatusOr<std::unique_ptr<KeysetManager>> KeysetManager::New(
    const KeyTemplate& key_template) {
  auto manager = util::make_unique<KeysetManager>();
  auto rotate_result = manager->Rotate(key_template);
  if (!rotate_result.ok()) return rotate_result.status();
  return std::move(manager);
}

// static
StatusOr<std::unique_ptr<KeysetManager>> KeysetManager::New(
    const KeysetHandle& keyset_handle) {
  auto manager = util::make_unique<KeysetManager>();
  manager->keyset_ = keyset_handle.get_keyset();
  return std::move(manager);
}

uint32_t KeysetManager::GenerateNewKeyId() {
  std::lock_guard<std::recursive_mutex> lock(keyset_mutex_);
  while (true) {
    uint32_t key_id = NewKeyId();
    bool already_exists = false;
    for (auto& key : keyset_.key()) {
      if (key.key_id() == key_id) {
        already_exists = true;
        break;
      }
    }
    if (!already_exists) return key_id;
  }
}

std::unique_ptr<KeysetHandle> KeysetManager::GetKeysetHandle() {
  std::lock_guard<std::recursive_mutex> lock(keyset_mutex_);
  std::unique_ptr<Keyset> keyset_copy(new Keyset(keyset_));
  std::unique_ptr<KeysetHandle> handle(
      new KeysetHandle(std::move(keyset_copy)));
  return handle;
}

StatusOr<uint32_t> KeysetManager::Add(const KeyTemplate& key_template) {
  std::lock_guard<std::recursive_mutex> lock(keyset_mutex_);
  auto key_data_result = Registry::NewKeyData(key_template);
  if (!key_data_result.ok()) return key_data_result.status();
  auto key_data = std::move(key_data_result.ValueOrDie());
  Keyset::Key* key = keyset_.add_key();
  uint32_t key_id = GenerateNewKeyId();
  *(key->mutable_key_data()) = *key_data;
  key->set_status(KeyStatusType::ENABLED);
  key->set_key_id(key_id);
  key->set_output_prefix_type(key_template.output_prefix_type());
  return key_id;
}

StatusOr<uint32_t> KeysetManager::Rotate(const KeyTemplate& key_template) {
  std::lock_guard<std::recursive_mutex> lock(keyset_mutex_);
  auto add_result = Add(key_template);
  if (!add_result.ok()) return add_result.status();
  auto key_id = add_result.ValueOrDie();
  auto status = SetPrimary(key_id);
  if (!status.ok()) return status;
  return key_id;
}

Status KeysetManager::Enable(uint32_t key_id) {
  std::lock_guard<std::recursive_mutex> lock(keyset_mutex_);
  for (auto& key : *(keyset_.mutable_key())) {
    if (key.key_id() == key_id) {
      if (key.status() != KeyStatusType::DISABLED &&
          key.status() != KeyStatusType::ENABLED) {
        return ToStatusF(util::error::INVALID_ARGUMENT,
                         "Cannot enable key with key_id %" PRIu32
                         " and status %s.",
                         key_id, KeyStatusType_Name(key.status()).c_str());
      }
      key.set_status(KeyStatusType::ENABLED);
      return Status::OK;
    }
  }
  return ToStatusF(util::error::NOT_FOUND,
                   "No key with key_id %" PRIu32 " found in the keyset.",
                   key_id);
}

Status KeysetManager::Disable(uint32_t key_id) {
  std::lock_guard<std::recursive_mutex> lock(keyset_mutex_);
  if (keyset_.primary_key_id() == key_id) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Cannot disable primary key (key_id %" PRIu32 ").",
                     key_id);
  }
  for (auto& key : *(keyset_.mutable_key())) {
    if (key.key_id() == key_id) {
      if (key.status() != KeyStatusType::DISABLED &&
          key.status() != KeyStatusType::ENABLED) {
        return ToStatusF(util::error::INVALID_ARGUMENT,
                         "Cannot disable key with key_id %" PRIu32
                         " and status %s.",
                         key_id, KeyStatusType_Name(key.status()).c_str());
      }
      key.set_status(KeyStatusType::DISABLED);
      return Status::OK;
    }
  }
  return ToStatusF(util::error::NOT_FOUND,
                   "No key with key_id %" PRIu32 " found in the keyset.",
                   key_id);
}

Status KeysetManager::Delete(uint32_t key_id) {
  std::lock_guard<std::recursive_mutex> lock(keyset_mutex_);
  if (keyset_.primary_key_id() == key_id) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Cannot delete primary key (key_id %" PRIu32 ").",
                     key_id);
  }
  auto key_field = keyset_.mutable_key();
  for (auto key_iter = key_field->begin();
       key_iter != key_field->end();
       key_iter++) {
    auto key = *key_iter;
    if (key.key_id() == key_id) {
      keyset_.mutable_key()->erase(key_iter);
      return Status::OK;
    }
  }
  return ToStatusF(util::error::NOT_FOUND,
                   "No key with key_id %" PRIu32 " found in the keyset.",
                   key_id);
}

Status KeysetManager::Destroy(uint32_t key_id) {
  std::lock_guard<std::recursive_mutex> lock(keyset_mutex_);
  if (keyset_.primary_key_id() == key_id) {
    return ToStatusF(util::error::INVALID_ARGUMENT,
                     "Cannot destroy primary key (key_id %" PRIu32 ").",
                     key_id);
  }
  for (auto& key : *(keyset_.mutable_key())) {
    if (key.key_id() == key_id) {
      if (key.status() != KeyStatusType::DISABLED &&
          key.status() != KeyStatusType::DESTROYED &&
          key.status() != KeyStatusType::ENABLED) {
        return ToStatusF(util::error::INVALID_ARGUMENT,
                         "Cannot destroy key with key_id %" PRIu32
                         " and status %s.",
                         key_id, KeyStatusType_Name(key.status()).c_str());
      }
      key.clear_key_data();
      key.set_status(KeyStatusType::DESTROYED);
      return Status::OK;
    }
  }
  return ToStatusF(util::error::NOT_FOUND,
                   "No key with key_id %" PRIu32 " found in the keyset.",
                   key_id);
}

Status KeysetManager::SetPrimary(uint32_t key_id) {
  std::lock_guard<std::recursive_mutex> lock(keyset_mutex_);
  for (auto& key : keyset_.key()) {
    if (key.key_id() == key_id) {
      if (key.status() != KeyStatusType::ENABLED) {
        return ToStatusF(util::error::INVALID_ARGUMENT,
                         "The candidate for the primary key must be ENABLED"
                         " (key_id %" PRIu32 ").", key_id);
      }
      keyset_.set_primary_key_id(key_id);
      return Status::OK;
    }
  }
  return ToStatusF(util::error::NOT_FOUND,
                   "No key with key_id %" PRIu32 " found in the keyset.",
                   key_id);
}

}  // namespace tink
}  // namespace crypto
