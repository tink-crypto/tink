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

#ifndef TINK_SUBTLE_HKDF_H_
#define TINK_SUBTLE_HKDF_H_

#include "cc/util/status.h"
#include "cc/util/statusor.h"
#include "google/protobuf/stubs/stringpiece.h"
#include "proto/common.pb.h"

using google::cloud::crypto::tink::HashType;
using google::protobuf::StringPiece;

namespace cloud {
namespace crypto {
namespace tink {

class Hkdf {
 public:
  // Computes hkdf according to RFC5869.
  static util::StatusOr<std::string> ComputeHkdf(HashType hash, StringPiece ikm,
                                                 StringPiece salt,
                                                 StringPiece info,
                                                 size_t out_len);
};

}  // namespace tink
}  // namespace crypto
}  // namespace cloud

#endif  // TINK_SUBTLE_HKDF_H_
