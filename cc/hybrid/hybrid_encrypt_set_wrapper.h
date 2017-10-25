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

#ifndef TINK_HYBRID_HYBRID_ENCRYPT_SET_WRAPPER_H_
#define TINK_HYBRID_HYBRID_ENCRYPT_SET_WRAPPER_H_

#include "absl/strings/string_view.h"
#include "cc/hybrid_encrypt.h"
#include "cc/primitive_set.h"
#include "cc/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// Wraps a set of HybridEncrypt-instances that correspond to a keyset,
// and combines them into a single HybridEncrypt-primitive, that uses
// the primary instance to do the actual encryption.
class HybridEncryptSetWrapper : public HybridEncrypt {
 public:
  // Returns an HybridEncrypt-primitive that uses the primary
  // HybridEncrypt-instance provided in 'hybrid_encrypt_set',
  // which must be non-NULL (and must contain a primary instance).
  static crypto::tink::util::StatusOr<std::unique_ptr<HybridEncrypt>>
      NewHybridEncrypt(
          std::unique_ptr<PrimitiveSet<HybridEncrypt>> hybrid_encrypt_set);

  crypto::tink::util::StatusOr<std::string> Encrypt(
      absl::string_view plaintext,
      absl::string_view context_info) const override;

  virtual ~HybridEncryptSetWrapper() {}

 private:
  std::unique_ptr<PrimitiveSet<HybridEncrypt>> hybrid_encrypt_set_;

  HybridEncryptSetWrapper(
      std::unique_ptr<PrimitiveSet<HybridEncrypt>> hybrid_encrypt_set)
      : hybrid_encrypt_set_(std::move(hybrid_encrypt_set)) {}
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_HYBRID_ENCRYPT_SET_WRAPPER_H_
