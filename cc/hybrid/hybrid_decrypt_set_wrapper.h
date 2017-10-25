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

#ifndef TINK_HYBRID_HYBRID_DECRYPT_SET_WRAPPER_H_
#define TINK_HYBRID_HYBRID_DECRYPT_SET_WRAPPER_H_

#include "absl/strings/string_view.h"
#include "cc/hybrid_decrypt.h"
#include "cc/primitive_set.h"
#include "cc/util/statusor.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// Wraps a set of HybridDecrypt-instances that correspond to a keyset,
// and combines them into a single HybridDecrypt-primitive, that for
// actual decryption uses the instance that matches the ciphertext prefix.
class HybridDecryptSetWrapper : public HybridDecrypt {
 public:
  // Returns an HybridDecrypt-primitive that uses HybridDecrypt-instances
  // provided in 'hybrid_decrypt_set', which must be non-NULL.
  static crypto::tink::util::StatusOr<std::unique_ptr<HybridDecrypt>>
      NewHybridDecrypt(
          std::unique_ptr<PrimitiveSet<HybridDecrypt>> hybrid_decrypt_set);

  crypto::tink::util::StatusOr<std::string> Decrypt(
      absl::string_view ciphertext,
      absl::string_view context_info) const override;

  virtual ~HybridDecryptSetWrapper() {}

 private:
  std::unique_ptr<PrimitiveSet<HybridDecrypt>> hybrid_decrypt_set_;

  HybridDecryptSetWrapper(
      std::unique_ptr<PrimitiveSet<HybridDecrypt>> hybrid_decrypt_set)
      : hybrid_decrypt_set_(std::move(hybrid_decrypt_set)) {}
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_HYBRID_HYBRID_DECRYPT_SET_WRAPPER_H_
