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

#ifndef TINK_MAC_MAC_CONFIG_H_
#define TINK_MAC_MAC_CONFIG_H_

#include "tink/util/status.h"
#include "proto/config.pb.h"

namespace crypto {
namespace tink {

///////////////////////////////////////////////////////////////////////////////
// Static methods and constants for registering with the Registry
// all instances of Mac key types supported in a particular release of Tink.
//
// To register all Mac key types provided in Tink release 1.1.0 one can do:
//
//   auto status = Config::Register(MacConfig::Tink_1_1_0());
//
// For more information on creation and usage of Mac instances see MacFactory.
class MacConfig {
 public:
  static constexpr char kCatalogueName[] = "TinkMac";
  static constexpr char kPrimitiveName[] = "Mac";

  // Returns config of Mac implementations supported in Tink 1.1.0.
  static const google::crypto::tink::RegistryConfig& Tink_1_1_0();

  // Initialization: registers the catalogue of Tink Mac-implementations.
  static crypto::tink::util::Status Init();

  // Registers standard Mac key types and their managers with the Registry.
  // DEPRECATED.
  static crypto::tink::util::Status RegisterStandardKeyTypes();

 private:
  MacConfig() {}
};

}  // namespace tink
}  // namespace crypto

#endif  // TINK_MAC_MAC_CONFIG_H_
