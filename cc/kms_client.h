// Copyright 2018 Google LLC
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

#ifndef TINK_KMS_CLIENT_H_
#define TINK_KMS_CLIENT_H_

#include <memory>

#include "absl/strings/string_view.h"
#include "tink/aead.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {

// KmsClient knows how to produce primitives backed by keys stored
// in remote KMS services.
class KmsClient {
 public:
  // Returns true iff this client does support KMS key specified by 'key_uri'.
  virtual bool DoesSupport(absl::string_view key_uri) const = 0;

  // Returns an Aead-primitive backed by KMS key specified by 'key_uri',
  // provided that this KmsClient does support 'key_uri'.
  virtual crypto::tink::util::StatusOr<std::unique_ptr<Aead>>
  GetAead(absl::string_view key_uri) const = 0;

  virtual ~KmsClient() {}
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_KMS_CLIENT_H_
