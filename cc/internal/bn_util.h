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
#ifndef TINK_INTERNAL_BN_UTIL_H_
#define TINK_INTERNAL_BN_UTIL_H_

#include <string>

#include "openssl/bn.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/util/secret_data.h"
#include "tink/util/statusor.h"

namespace crypto {
namespace tink {
namespace internal {

// Compares `bignum` with the given `word`. It returns a result < 0 if `bignum`
// < `word`, 0 if `bignum` == `word`, and > 0 if `bignum` > `word`.
int CompareBignumWithWord(const BIGNUM* bignum, BN_ULONG word);

// Converts the absolute value of `bignum` into a big-endian form, and writes it
// in `buffer`.
crypto::tink::util::Status BignumToBinaryPadded(absl::Span<char> buffer,
                                                const BIGNUM* bignum);

// Retuns a string that encodes `bn` in big-endian form of size `len` with
// leading zeroes.
crypto::tink::util::StatusOr<std::string> BignumToString(const BIGNUM* bn,
                                                         size_t len);

// Retuns a SecretData object that encodes `bn` in big-endian form of size `len`
// with leading zeroes.
crypto::tink::util::StatusOr<crypto::tink::util::SecretData> BignumToSecretData(
    const BIGNUM* bn, size_t len);

// Returns an OpenSSL/BoringSSL BIGNUM constructed from a bigendian string
// representation `bigendian_bn_str`.
crypto::tink::util::StatusOr<internal::SslUniquePtr<BIGNUM>> StringToBignum(
    absl::string_view bigendian_bn_str);

}  // namespace internal
}  // namespace tink
}  // namespace crypto

#endif  // TINK_INTERNAL_BN_UTIL_H_
