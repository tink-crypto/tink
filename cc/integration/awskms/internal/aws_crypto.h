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

#ifndef TINK_INTEGRATION_AWSKMS_AWS_CRYPTO_H_
#define TINK_INTEGRATION_AWSKMS_AWS_CRYPTO_H_

#include "aws/core/Aws.h"
#include "aws/core/utils/crypto/Factories.h"
#include "aws/core/utils/crypto/HMAC.h"
#include "aws/core/utils/crypto/Hash.h"

namespace crypto {
namespace tink {
namespace internal {

// Helpers for building AWS C++ Client without OpenSSL, to avoid
// collisions with BoringSSL used by Tink.
// These were "borrowed" from TensorFlow (https://github.com/tensorflow/).
//
// With these helpers the initialization of AWS API looks as follows:
//
//   Aws::SDKOptions options;
//   options.cryptoOptions.sha256Factory_create_fn = []() {
//       return Aws::MakeShared<AwsSha256Factory>(kAwsCryptoAllocationTag);
//   };
//   options.cryptoOptions.sha256HMACFactory_create_fn = []() {
//       return Aws::MakeShared<AwsSha256HmacFactory>(kAwsCryptoAllocationTag);
//   };
//   Aws::InitAPI(options);
//
///////////////////////////////////////////////////////////////////////////////

extern const char* kAwsCryptoAllocationTag;

class AwsSha256Factory : public Aws::Utils::Crypto::HashFactory {
 public:
  AwsSha256Factory() = default;
  // Move only.
  AwsSha256Factory(AwsSha256Factory&& other) = default;
  AwsSha256Factory& operator=(AwsSha256Factory&& other) = default;
  AwsSha256Factory(const AwsSha256Factory&) = delete;
  AwsSha256Factory& operator=(const AwsSha256Factory&) = delete;

  std::shared_ptr<Aws::Utils::Crypto::Hash> CreateImplementation()
      const override;
};

class AwsSha256HmacFactory : public Aws::Utils::Crypto::HMACFactory {
 public:
  AwsSha256HmacFactory() = default;
  // Move only.
  AwsSha256HmacFactory(AwsSha256HmacFactory&& other) = default;
  AwsSha256HmacFactory& operator=(AwsSha256HmacFactory&& other) = default;
  AwsSha256HmacFactory(const AwsSha256HmacFactory&) = delete;
  AwsSha256HmacFactory& operator=(const AwsSha256HmacFactory&) = delete;

  std::shared_ptr<Aws::Utils::Crypto::HMAC> CreateImplementation()
      const override;
};

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTEGRATION_AWSKMS_AWS_CRYPTO_H_
