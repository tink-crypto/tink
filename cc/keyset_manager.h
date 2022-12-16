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
#ifndef TINK_KEYSET_MANAGER_H_
#define TINK_KEYSET_MANAGER_H_

#include <memory>

#include "absl/base/thread_annotations.h"
#include "absl/synchronization/mutex.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

class KeysetHandle;

// KeysetManager provides convenience methods for creation of Keysets, and for
// rotating, disabling, enabling, or destroying keys.
// An instance of this class takes care of a single Keyset, that can be
// accessed via GetKeysetHandle()-method.
class KeysetManager {
 public:
  // Constructs a KeysetManager with an empty Keyset.
  KeysetManager() = default;

  // Creates a new KeysetManager that contains a Keyset with a single key
  // generated freshly according the specification in 'key_template'.
  static crypto::tink::util::StatusOr<std::unique_ptr<KeysetManager>> New(
      const google::crypto::tink::KeyTemplate& key_template);

  // Creates a new KeysetManager that contains a Keyset cloned from
  // the given 'keyset_handle'.
  static crypto::tink::util::StatusOr<std::unique_ptr<KeysetManager>> New(
      const KeysetHandle& keyset_handle);

  // Adds to the managed keyset a fresh key generated according to
  // 'keyset_template' and returns the key_id of the added key.
  // The added key has status 'ENABLED'.
  crypto::tink::util::StatusOr<uint32_t> Add(
      const google::crypto::tink::KeyTemplate& key_template)
      ABSL_LOCKS_EXCLUDED(keyset_mutex_);

  // Adds to the managed keyset a fresh key generated according to
  // 'keyset_template', sets the new key as the primary,
  // and returns the key_id of the added key.
  // The key that was primary prior to rotation remains 'ENABLED'.
  crypto::tink::util::StatusOr<uint32_t> Rotate(
      const google::crypto::tink::KeyTemplate& key_template)
      ABSL_LOCKS_EXCLUDED(keyset_mutex_);

  // Sets the status of the specified key to 'ENABLED'.
  // Succeeds only if before the call the specified key
  // has status 'DISABLED' or 'ENABLED'.
  crypto::tink::util::Status Enable(uint32_t key_id)
      ABSL_LOCKS_EXCLUDED(keyset_mutex_);

  // Sets the status of the specified key to 'DISABLED'.
  // Succeeds only if before the call the specified key
  // is not primary and has status 'DISABLED' or 'ENABLED'.
  crypto::tink::util::Status Disable(uint32_t key_id)
      ABSL_LOCKS_EXCLUDED(keyset_mutex_);

  // Sets the status of the specified key to 'DESTROYED',
  // and removes the corresponding key material, if any.
  // Succeeds only if before the call the specified key
  // is not primary and has status 'DISABLED', or 'ENABLED',
  // or 'DESTROYED'.
  crypto::tink::util::Status Destroy(uint32_t key_id)
      ABSL_LOCKS_EXCLUDED(keyset_mutex_);

  // Removes the specifed key from the managed keyset.
  // Succeeds only if the specified key is not primary.
  // After deletion the keyset contains one key fewer.
  crypto::tink::util::Status Delete(uint32_t key_id)
      ABSL_LOCKS_EXCLUDED(keyset_mutex_);

  // Sets the specified key as the primary.
  // Succeeds only if the specified key is 'ENABLED'.
  crypto::tink::util::Status SetPrimary(uint32_t key_id)
      ABSL_LOCKS_EXCLUDED(keyset_mutex_);

  // Returns the count of all keys in the keyset.
  int KeyCount() const;

  // Returns a handle with a copy of the managed keyset.
  std::unique_ptr<KeysetHandle> GetKeysetHandle()
      ABSL_LOCKS_EXCLUDED(keyset_mutex_);

 private:
  crypto::tink::util::StatusOr<uint32_t> Add(
      const google::crypto::tink::KeyTemplate& key_template, bool as_primary)
      ABSL_LOCKS_EXCLUDED(keyset_mutex_);

  mutable absl::Mutex keyset_mutex_;
  google::crypto::tink::Keyset keyset_ ABSL_GUARDED_BY(keyset_mutex_);
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEYSET_MANAGER_H_
