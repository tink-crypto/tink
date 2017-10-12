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

#ifndef TINK_KEYSET_HANDLE_H_
#define TINK_KEYSET_HANDLE_H_

#include "cc/aead.h"
#include "cc/keyset_reader.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// KeysetHandle provides abstracted access to Keysets, to limit
// the exposure of actual protocol buffers that hold sensitive
// key material.
class KeysetHandle {
 public:
  // TODO(przydatek): refactor to ensure that creation KeysetHandle-objects
  //   can be controlled (as in Java).

  // Creates a KeysetHandle from an encrypted keyset obtained via |reader|
  // using |master_key_aead| to decrypt the keyset.
  static crypto::tink::util::StatusOr<std::unique_ptr<KeysetHandle>> Read(
      std::unique_ptr<KeysetReader> reader, const Aead& master_key_aead);

  // Returns a new KeysetHandle that contains a single fresh key generated
  // according to |key_template|.
  static crypto::tink::util::StatusOr<std::unique_ptr<KeysetHandle>>
  GenerateNew(const google::crypto::tink::KeyTemplate& key_template);

  // Returns keyset held by this handle.
  // For internal use only, do not use outside Tink-code as it will be
  // deprecated/hidden soon.
  const google::crypto::tink::Keyset& get_keyset() const;

  // This constructor is here only so that ObjC code doesn't break.
  // TODO(b/64722726): remove the dependency and the constructor.
  explicit KeysetHandle(const google::crypto::tink::Keyset& keyset) {
    std::unique_ptr<google::crypto::tink::Keyset> keyset_copy(
        new google::crypto::tink::Keyset(keyset));
    keyset_ = std::move(keyset_copy);
  }

 private:
  friend class CleartextKeysetHandle;
  friend class KeysetManager;

  KeysetHandle(std::unique_ptr<google::crypto::tink::Keyset> keyset);
  std::unique_ptr<google::crypto::tink::Keyset> keyset_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEYSET_HANDLE_H_
