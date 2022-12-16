// Copyright 2018 Google Inc.
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

#ifndef TINK_KEYSET_WRITER_H_
#define TINK_KEYSET_WRITER_H_

#include "tink/util/status.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// KeysetWriter knows how to write a Keyset or an EncryptedKeyset
// to some storage system.
class KeysetWriter {
 public:
  // Writes 'keyset' to the underlying storage system.
  virtual crypto::tink::util::Status
      Write(const google::crypto::tink::Keyset& keyset) = 0;

  // Writes 'encrypted_keyset' to the underlying storage system.
  virtual crypto::tink::util::Status
      Write(const google::crypto::tink::EncryptedKeyset& encrypted_keyset) = 0;

  virtual ~KeysetWriter() = default;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEYSET_WRITER_H_
