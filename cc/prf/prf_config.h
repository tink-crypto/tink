// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////

#ifndef TINK_PRF_PRF_CONFIG_H_
#define TINK_PRF_PRF_CONFIG_H_

#include "tink/util/status.h"
#include "proto/tink.pb.h"

///////////////////////////////////////////////////////////////////////////////
// Static methods and constants for registering with the Registry
// all instances of Prf key types supported in a particular release of Tink.

namespace crypto {
namespace tink {

class PrfConfig {
 public:
  // Registers Prf key managers for all Prf key types from the current Tink
  // release.
  static crypto::tink::util::Status Register();
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_PRF_PRF_CONFIG_H_
