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

#ifndef TINK_UTIL_TEST_UTIL_H_
#define TINK_UTIL_TEST_UTIL_H_

#include <string>

#include "cc/aead.h"
#include "cc/mac.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "google/protobuf/stubs/stringpiece.h"

using google::protobuf::StringPiece;

namespace cloud {
namespace crypto {
namespace tink {
namespace test {

// Various utilities for testing.
///////////////////////////////////////////////////////////////////////////////

// Converts a hexadecimal string into a string of bytes.
// Returns a status if the size of the input is odd or if the input contains
// characters that are not hexadecimal.
util::StatusOr<std::string> HexDecode(google::protobuf::StringPiece hex) {
  if (hex.size() % 2 != 0) {
    return util::Status(util::error::INVALID_ARGUMENT, "Input has odd size.");
  }
  std::string decoded(hex.size() / 2, static_cast<char>(0));
  for (int i = 0; i < hex.size(); ++i) {
    char c = hex[i];
    char val;
    if ('0' <= c && c <= '9')
      val = c - '0';
    else if ('a' <= c && c <= 'f')
      val = c - 'a' + 10;
    else if ('A' <= c && c <= 'F')
      val = c - 'A' + 10;
    else
      return util::Status(util::error::INVALID_ARGUMENT, "Not hexadecimal");
    decoded[i / 2] = (decoded[i / 2] << 4) | val;
  }
  return decoded;
}

// Converts a hexadecimal string into a string of bytes.
// Dies if the input is not a valid hexadecimal string.
std::string HexDecodeOrDie(google::protobuf::StringPiece hex) {
  return HexDecode(hex).ValueOrDie();
}

// Converts a string of bytes into a hexadecimal string.
std::string HexEncode(google::protobuf::StringPiece bytes) {
  std::string hexchars = "0123456789abcdef";
  std::string res(bytes.size() * 2, static_cast<char>(255));
  for (int i = 0; i < bytes.size(); ++i) {
    uint8_t c = static_cast<uint8_t>(bytes[i]);
    res[2 * i] = hexchars[c / 16];
    res[2 * i + 1] = hexchars[c % 16];
  }
  return res;
}

// A dummy implementation of Aead-interface.
// An instance of DummyAead can be identified by a name specified
// as a parameter of the constructor.
class DummyAead : public Aead {
 public:
  DummyAead(const std::string& aead_name) : aead_name_(aead_name) {}

  // Computes a dummy ciphertext, which is concatenation of provided 'plaintext'
  // with the name of this DummyAead.
  util::StatusOr<std::string> Encrypt(
      const StringPiece& plaintext,
      const StringPiece& additional_data) const override {
    return plaintext.ToString().append(aead_name_);
  }

  util::StatusOr<std::string> Decrypt(
      const StringPiece& ciphertext,
      const StringPiece& additional_data) const override {
    std::string c = ciphertext.ToString();
    size_t pos = c.rfind(aead_name_);
    if (pos != std::string::npos &&
        ciphertext.length() == (unsigned)(aead_name_.length() + pos)) {
      return c.substr(0, pos);
    }
    return util::Status(util::error::INVALID_ARGUMENT, "Wrong ciphertext.");
  }

 private:
  std::string aead_name_;
};

// A dummy implementation of Mac-interface.
// An instance of DummyMac can be identified by a name specified
// as a parameter of the constructor.
class DummyMac : public Mac {
 public:
  DummyMac(const std::string mac_name) : mac_name_(mac_name) {}

  // Computes a dummy MAC, which is concatenation of provided 'data'
  // with the name of this DummyMac.
  util::StatusOr<std::string> ComputeMac(
      google::protobuf::StringPiece data) const override {
    return data.ToString().append(mac_name_);
  }

  util::Status VerifyMac(
      google::protobuf::StringPiece mac,
      google::protobuf::StringPiece data) const override {
    if (mac == (data.ToString().append(mac_name_))) {
      return util::Status::OK;
    } else {
      return util::Status(util::error::INVALID_ARGUMENT, "Wrong MAC.");
    }
  }
 private:
  std::string mac_name_;
};


}  // namespace test
}  // namespace tink
}  // namespace crypto
}  // namespace cloud

#endif  // TINK_UTIL_TEST_UTIL_H_
