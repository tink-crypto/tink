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

#include "tink/crypto_format.h"

#include <cstdint>
#include <string>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "tink/util/errors.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "proto/tink.pb.h"

using google::crypto::tink::OutputPrefixType;

namespace crypto {
namespace tink {

namespace {
// Writes bytes of 'value' in Big Endian order to 'buf'.
// 'buf' must have at least 4 bytes allocated.
void uint32_as_big_endian(uint32_t value, char* buf) {
  buf[0] = 0xff & (value >> 24);
  buf[1] = 0xff & (value >> 16);
  buf[2] = 0xff & (value >> 8);
  buf[3] = 0xff & (value >> 0);
}

}  // anonymous namespace

const int CryptoFormat::kNonRawPrefixSize;
const int CryptoFormat::kLegacyPrefixSize;
const uint8_t CryptoFormat::kLegacyStartByte;

const int CryptoFormat::kTinkPrefixSize;
const uint8_t CryptoFormat::kTinkStartByte;

const int CryptoFormat::kRawPrefixSize;
const absl::string_view CryptoFormat::kRawPrefix = "";

// static
crypto::tink::util::StatusOr<std::string> CryptoFormat::GetOutputPrefix(
    const google::crypto::tink::KeysetInfo::KeyInfo& key_info) {
  static_assert(sizeof(key_info.key_id() == sizeof(uint32_t )), "");
  switch (key_info.output_prefix_type()) {
    case OutputPrefixType::TINK: {
      static_assert(kTinkPrefixSize == 1 + sizeof(uint32_t), "");
      std::string prefix(kTinkPrefixSize, '\0');
      prefix[0] = kTinkStartByte;
      uint32_as_big_endian(key_info.key_id(), &prefix[1]);
      return prefix;
    }
    case OutputPrefixType::CRUNCHY:
      // FALLTHROUGH
    case OutputPrefixType::LEGACY: {
      static_assert(kLegacyPrefixSize == 1 + sizeof(uint32_t), "");
      std::string prefix(kLegacyPrefixSize, '\0');
      prefix[0] = kLegacyStartByte;
      uint32_as_big_endian(key_info.key_id(), &prefix[1]);
      return prefix;
    }
    case OutputPrefixType::RAW:
      return std::string(kRawPrefix);
    default:
      return util::Status(absl::StatusCode::kInvalidArgument,
                          "The given key has invalid OutputPrefixType.");
  }
}

}  // namespace tink
}  // namespace crypto
