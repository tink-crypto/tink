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

#ifndef TINK_KEYSET_READER_H_
#define TINK_KEYSET_READER_H_

#include <memory>

#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// KeysetReader knows how to read a Keyset or an EncryptedKeyset
// from some source.
class KeysetReader {
 public:
  // Reads and returns a (cleartext) Keyset object from the underlying source.
  virtual crypto::tink::util::StatusOr<
   std::unique_ptr<google::crypto::tink::Keyset>>
  Read() = 0;

  // Reads and returns an EncryptedKeyset object from the underlying source.
  virtual crypto::tink::util::StatusOr<
    std::unique_ptr<google::crypto::tink::EncryptedKeyset>>
  ReadEncrypted() = 0;

  virtual ~KeysetReader() {}
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_KEYSET_READER_H_
