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

#ifndef TINK_BINARY_KEYSET_READER_H_
#define TINK_BINARY_KEYSET_READER_H_

#include <istream>
#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "tink/keyset_reader.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// A KeysetReader that can read from some source cleartext or
// encrypted keysets in proto binary wire format, cf.
// https://developers.google.com/protocol-buffers/docs/encoding
class BinaryKeysetReader : public KeysetReader {
 public:
  static crypto::tink::util::StatusOr<std::unique_ptr<KeysetReader>> New(
      std::unique_ptr<std::istream> keyset_stream);
  static crypto::tink::util::StatusOr<std::unique_ptr<KeysetReader>> New(
      absl::string_view serialized_keyset);

  crypto::tink::util::StatusOr<std::unique_ptr<google::crypto::tink::Keyset>>
  Read() override;

  crypto::tink::util::StatusOr<
    std::unique_ptr<google::crypto::tink::EncryptedKeyset>>
  ReadEncrypted() override;

 private:
  explicit BinaryKeysetReader(absl::string_view serialized_keyset)
      : serialized_keyset_(serialized_keyset) {}

  std::string serialized_keyset_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_BINARY_KEYSET_READER_H_
