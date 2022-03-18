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

#ifndef TINK_CRYPTO_FORMAT_H_
#define TINK_CRYPTO_FORMAT_H_

#include <string>
#include <vector>

#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// Constants and convenience methods that deal with the format
// of the outputs handled by Tink.
class CryptoFormat {
 public:
  // Prefix size of Tink and Legacy key types.
  static constexpr int kNonRawPrefixSize = 5;

  // Legacy prefix starts with \x00 and followed by a 4-byte key id.
  static constexpr int kLegacyPrefixSize = kNonRawPrefixSize;
  static constexpr uint8_t kLegacyStartByte = 0x00;

  // Tink prefix starts with \x01 and followed by a 4-byte key id.
  static constexpr int kTinkPrefixSize = kNonRawPrefixSize;
  static constexpr uint8_t kTinkStartByte = 0x01;

  // Raw prefix is empty.
  static constexpr int kRawPrefixSize = 0;
  static const absl::string_view kRawPrefix;  // empty string

  // Generates the prefix for the outputs handled with the given key_info.
  // Returns an error if the prefix type 'output_prefix_type' is invalid.
  static crypto::tink::util::StatusOr<std::string> GetOutputPrefix(
      const google::crypto::tink::KeysetInfo::KeyInfo& key_info);
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_CRYPTO_FORMAT_H_
