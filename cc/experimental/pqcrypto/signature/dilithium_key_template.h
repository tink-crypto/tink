// Copyright 2021 Google LLC
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

#ifndef TINK_EXPERIMENTAL_SIGNATURE_DILITHIUM_KEY_TEMPLATE_H_
#define TINK_EXPERIMENTAL_SIGNATURE_DILITHIUM_KEY_TEMPLATE_H_

#include "proto/tink.pb.h"

namespace crypto {
namespace tink {

// Returns a KeyTemplate that generates new instances of DilithiumPrivateKey.
const google::crypto::tink::KeyTemplate& Dilithium2KeyTemplate();

const google::crypto::tink::KeyTemplate& Dilithium3KeyTemplate();

const google::crypto::tink::KeyTemplate& Dilithium5KeyTemplate();

const google::crypto::tink::KeyTemplate& Dilithium2AesKeyTemplate();

const google::crypto::tink::KeyTemplate& Dilithium3AesKeyTemplate();

const google::crypto::tink::KeyTemplate& Dilithium5AesKeyTemplate();

}  // namespace tink
}  // namespace crypto

#endif  // TINK_EXPERIMENTAL_SIGNATURE_DILITHIUM_KEY_TEMPLATE_H_
