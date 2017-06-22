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

#include "cc/subtle/hkdf.h"

#include "cc/subtle/subtle_util_boringssl.h"
#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "openssl/evp.h"
#include "openssl/hkdf.h"

using google::crypto::tink::HashType;
using google::protobuf::StringPiece;

namespace crypto {
namespace tink {

// static
util::StatusOr<std::string> Hkdf::ComputeHkdf(HashType hash,
                                              StringPiece ikm,
                                              StringPiece salt,
                                              StringPiece info,
                                              size_t out_len) {
  auto status_or_evp_md = SubtleUtilBoringSSL::EvpHash(hash);
  if (!status_or_evp_md.ok()) {
    return status_or_evp_md.status();
  }
  std::unique_ptr<uint8_t[]> out_key(new uint8_t[out_len]);
  if (1 != HKDF(out_key.get(), out_len, status_or_evp_md.ValueOrDie(),
                reinterpret_cast<const uint8_t *>(ikm.data()), ikm.size(),
                reinterpret_cast<const uint8_t *>(salt.data()), salt.size(),
                reinterpret_cast<const uint8_t *>(info.data()), info.size())) {
    return util::Status(util::error::INTERNAL, "BoringSSL's HKDF failed");
  }
  return std::string(reinterpret_cast<const char *>(out_key.get()), out_len);
}

// static
util::StatusOr<std::string> Hkdf::ComputeEciesHkdfSymmetricKey(
    HashType hash,
    StringPiece kem_bytes,
    StringPiece shared_secret,
    StringPiece salt,
    StringPiece info,
    size_t out_len) {
  std::string ikm(kem_bytes);
  std::string shared_secret_string(shared_secret);
  ikm.append(shared_secret_string);
  return Hkdf::ComputeHkdf(hash, ikm, salt, info, out_len);
}

}  // namespace tink
}  // namespace crypto
