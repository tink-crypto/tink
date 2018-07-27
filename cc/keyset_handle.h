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

#include "tink/aead.h"
#include "tink/keyset_reader.h"
#include "tink/keyset_writer.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// KeysetHandle provides abstracted access to Keysets, to limit
// the exposure of actual protocol buffers that hold sensitive
// key material.
class KeysetHandle {
 public:
  // Creates a KeysetHandle from an encrypted keyset obtained via |reader|
  // using |master_key_aead| to decrypt the keyset.
  static crypto::tink::util::StatusOr<std::unique_ptr<KeysetHandle>> Read(
      std::unique_ptr<KeysetReader> reader, const Aead& master_key_aead);

  // Returns a new KeysetHandle that contains a single fresh key generated
  // according to |key_template|.
  static crypto::tink::util::StatusOr<std::unique_ptr<KeysetHandle>>
  GenerateNew(const google::crypto::tink::KeyTemplate& key_template);

  // Encrypts the underlying keyset with the provided |master_key_aead|
  // and writes the resulting EncrytpedKeyset to the given |writer|,
  // which must be non-null.
  crypto::tink::util::Status  Write(KeysetWriter* writer,
      const Aead& master_key_aead);

  // Returns a new KeysetHandle that contains public keys corresponding
  // to the private keys from this handle.
  // Returns an error if this handle contains keys that are not private keys.
  crypto::tink::util::StatusOr<std::unique_ptr<KeysetHandle>>
  GetPublicKeysetHandle();


 private:
  // The classes below need access to get_keyset();
  friend class CleartextKeysetHandle;
  friend class KeysetManager;
  friend class Registry;

  // KeysetUtil::GetKeyset() provides access to get_keyset().
  friend class KeysetUtil;

  // Returns keyset held by this handle.
  const google::crypto::tink::Keyset& get_keyset() const;

  // Creates a handle that contains and owns the given keyset.
  KeysetHandle(std::unique_ptr<google::crypto::tink::Keyset> keyset);
  std::unique_ptr<google::crypto::tink::Keyset> keyset_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEYSET_HANDLE_H_
