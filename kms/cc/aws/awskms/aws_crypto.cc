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

#include "awskms/aws_crypto.h"

#include "aws/core/Aws.h"
#include "aws/core/utils/Outcome.h"
#include "aws/core/utils/crypto/Factories.h"
#include "aws/core/utils/crypto/HashResult.h"
#include "aws/core/utils/crypto/HMAC.h"
#include "aws/core/utils/crypto/Hash.h"

#include "absl/base/attributes.h"
#include "openssl/hmac.h"
#include "openssl/sha.h"

namespace crypto {
namespace tink {
namespace integration {
namespace awskms {

ABSL_CONST_INIT const char* kAwsCryptoAllocationTag = "AwsCryptoAllocation";

class AwsSha256HmacOpenSslImpl : public Aws::Utils::Crypto::HMAC {
 public:
  AwsSha256HmacOpenSslImpl() {}

  virtual ~AwsSha256HmacOpenSslImpl() = default;

  Aws::Utils::Crypto::HashResult Calculate(
      const Aws::Utils::ByteBuffer& toSign,
      const Aws::Utils::ByteBuffer& secret) override {
    unsigned int length = SHA256_DIGEST_LENGTH;
    Aws::Utils::ByteBuffer digest(length);
    memset(digest.GetUnderlyingData(), 0, length);

    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);

    HMAC_Init_ex(&ctx, secret.GetUnderlyingData(),
                 static_cast<int>(secret.GetLength()), EVP_sha256(), NULL);
    HMAC_Update(&ctx, toSign.GetUnderlyingData(), toSign.GetLength());
    HMAC_Final(&ctx, digest.GetUnderlyingData(), &length);
    HMAC_CTX_cleanup(&ctx);

    return Aws::Utils::Crypto::HashResult(std::move(digest));
  }
};

class AwsSha256OpenSslImpl : public Aws::Utils::Crypto::Hash {
 public:
  AwsSha256OpenSslImpl() {}

  virtual ~AwsSha256OpenSslImpl() = default;

  Aws::Utils::Crypto::HashResult Calculate(const Aws::String& str) override {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.data(), str.size());

    Aws::Utils::ByteBuffer hash(SHA256_DIGEST_LENGTH);
    SHA256_Final(hash.GetUnderlyingData(), &sha256);

    return Aws::Utils::Crypto::HashResult(std::move(hash));
  }

  Aws::Utils::Crypto::HashResult Calculate(Aws::IStream& stream) override {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    auto currentPos = stream.tellg();
    if (currentPos == std::streampos(std::streamoff(-1))) {
      currentPos = 0;
      stream.clear();
    }

    stream.seekg(0, stream.beg);

    char streamBuffer
        [Aws::Utils::Crypto::Hash::INTERNAL_HASH_STREAM_BUFFER_SIZE];
    while (stream.good()) {
      stream.read(streamBuffer,
                  Aws::Utils::Crypto::Hash::INTERNAL_HASH_STREAM_BUFFER_SIZE);
      auto bytesRead = stream.gcount();

      if (bytesRead > 0) {
        SHA256_Update(&sha256, streamBuffer, static_cast<size_t>(bytesRead));
      }
    }

    stream.clear();
    stream.seekg(currentPos, stream.beg);

    Aws::Utils::ByteBuffer hash(SHA256_DIGEST_LENGTH);
    SHA256_Final(hash.GetUnderlyingData(), &sha256);

    return Aws::Utils::Crypto::HashResult(std::move(hash));
  }
};

std::shared_ptr<Aws::Utils::Crypto::Hash>
AwsSha256Factory::CreateImplementation() const {
  return Aws::MakeShared<AwsSha256OpenSslImpl>(kAwsCryptoAllocationTag);
}

std::shared_ptr<Aws::Utils::Crypto::HMAC>
AwsSha256HmacFactory::CreateImplementation() const {
  return Aws::MakeShared<AwsSha256HmacOpenSslImpl>(kAwsCryptoAllocationTag);
}


}  // namespace awskms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
