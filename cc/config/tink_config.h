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

#ifndef TINK_CONFIG_TINK_CONFIG_H_
#define TINK_CONFIG_TINK_CONFIG_H_

#include "cc/util/status.h"
#include "proto/config.pb.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// Static methods and constants for registering with the Registry
// all instances of Tink key types supported in a particular release of Tink.
//
// To register all Tink key types provided in Tink release 1.1.0 one can do:
//
//   auto status = Config::Register(TinkConfig::Tink_1_1_0());
//
class TinkConfig {
 public:
  // Returns config of implementations of all primitives in Tink 1.1.0.
  static const google::crypto::tink::RegistryConfig& Tink_1_1_0();

  // Initialization: registers the catalogues of all Tink primitives.
  static crypto::tink::util::Status Init();

 private:
  TinkConfig() {}
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_CONFIG_TINK_CONFIG_H_
