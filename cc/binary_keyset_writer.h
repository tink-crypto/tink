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

#ifndef TINK_BINARY_KEYSET_WRITER_H_
#define TINK_BINARY_KEYSET_WRITER_H_

#include <memory>
#include <ostream>
#include <utility>

#include "absl/strings/string_view.h"
#include "tink/keyset_writer.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// A KeysetWriter that can write to some destination cleartext
// or encrypted keysets in proto binary wire format, cf.
// https://developers.google.com/protocol-buffers/docs/encoding
class BinaryKeysetWriter : public KeysetWriter {
 public:
  static crypto::tink::util::StatusOr<std::unique_ptr<BinaryKeysetWriter>> New(
      std::unique_ptr<std::ostream> destination_stream);

  crypto::tink::util::Status
  Write(const google::crypto::tink::Keyset& keyset) override;;

  crypto::tink::util::Status
  Write(const google::crypto::tink::EncryptedKeyset& encrypted_keyset) override;

 private:
  explicit BinaryKeysetWriter(std::unique_ptr<std::ostream> destination_stream)
      : destination_stream_(std::move(destination_stream)) {}

  std::unique_ptr<std::ostream> destination_stream_;
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_BINARY_KEYSET_WRITER_H_
