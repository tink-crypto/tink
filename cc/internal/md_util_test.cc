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
#include "tink/internal/md_util.h"

#include <cstdint>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/escaping.h"
#include "absl/types/span.h"
#include "openssl/evp.h"
#include "tink/subtle/common_enums.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace internal {
namespace {

using ::crypto::tink::subtle::HashType;
using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;
using ::testing::Not;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

TEST(MdUtil, EvpHashFromHashType) {
  EXPECT_THAT(EvpHashFromHashType(HashType::SHA1), IsOkAndHolds(EVP_sha1()));
  EXPECT_THAT(EvpHashFromHashType(HashType::SHA224),
              IsOkAndHolds(EVP_sha224()));
  EXPECT_THAT(EvpHashFromHashType(HashType::SHA256),
              IsOkAndHolds(EVP_sha256()));
  EXPECT_THAT(EvpHashFromHashType(HashType::SHA384),
              IsOkAndHolds(EVP_sha384()));
  EXPECT_THAT(EvpHashFromHashType(HashType::SHA512),
              IsOkAndHolds(EVP_sha512()));
  EXPECT_THAT(EvpHashFromHashType(HashType::UNKNOWN_HASH).status(),
              Not(IsOk()));
}

TEST(MdUtil, IsHashTypeSafeForSignature) {
  EXPECT_THAT(IsHashTypeSafeForSignature(HashType::SHA256), IsOk());
  EXPECT_THAT(IsHashTypeSafeForSignature(HashType::SHA384), IsOk());
  EXPECT_THAT(IsHashTypeSafeForSignature(HashType::SHA512), IsOk());
  EXPECT_THAT(IsHashTypeSafeForSignature(HashType::SHA1), Not(IsOk()));
  EXPECT_THAT(IsHashTypeSafeForSignature(HashType::SHA224), Not(IsOk()));
  EXPECT_THAT(IsHashTypeSafeForSignature(HashType::UNKNOWN_HASH), Not(IsOk()));
}

TEST(MdUtil, ComputeHashAcceptsNullStringView) {
  util::StatusOr<std::string> null_hash =
      ComputeHash(absl::string_view(nullptr, 0), *EVP_sha512());
  util::StatusOr<std::string> empty_hash = ComputeHash("", *EVP_sha512());
  std::string str;
  util::StatusOr<std::string> empty_str_hash = ComputeHash(str, *EVP_sha512());

  ASSERT_THAT(null_hash, IsOk());
  ASSERT_THAT(empty_hash, IsOk());
  ASSERT_THAT(empty_str_hash, IsOk());

  EXPECT_EQ(*null_hash, *empty_hash);
  EXPECT_EQ(*null_hash, *empty_str_hash);
}

struct MdUtilComputeHashSamplesTestParam {
  HashType hash_type;
  std::string data_hex;
  std::string expected_digest_hex;
};

using MdUtilComputeHashSamplesTest =
    TestWithParam<MdUtilComputeHashSamplesTestParam>;

// Returns the test parameters for MdUtilComputeHashSamplesTest from NIST's
// samples.
std::vector<MdUtilComputeHashSamplesTestParam>
GetMdUtilComputeHashSamplesTestParams() {
  std::vector<MdUtilComputeHashSamplesTestParam> params;
  params.push_back({
      HashType::SHA256,
      "af397a8b8dd73ab702ce8e53aa9f",
      "d189498a3463b18e846b8ab1b41583b0b7efc789dad8a7fb885bbf8fb5b45c5c",
  });
  params.push_back({
      HashType::SHA256,
      "59eb45bbbeb054b0b97334d53580ce03f699",
      "32c38c54189f2357e96bd77eb00c2b9c341ebebacc2945f97804f59a93238288",
  });
  params.push_back({
      HashType::SHA512,
      "16b17074d3e3d97557f9ed77d920b4b1bff4e845b345a922",
      "6884134582a760046433abcbd53db8ff1a89995862f305b887020f6da6c7b903a314721e"
      "972bf438483f452a8b09596298a576c903c91df4a414c7bd20fd1d07",
  });
  params.push_back({
      HashType::SHA512,
      "7651ab491b8fa86f969d42977d09df5f8bee3e5899180b52c968b0db057a6f02a886ad61"
      "7a84915a",
      "f35e50e2e02b8781345f8ceb2198f068ba103476f715cfb487a452882c9f0de0c720b2a0"
      "88a39d06a8a6b64ce4d6470dfeadc4f65ae06672c057e29f14c4daf9",
  });
  return params;
}

TEST_P(MdUtilComputeHashSamplesTest, ComputesHash) {
  const MdUtilComputeHashSamplesTestParam& params = GetParam();
  util::StatusOr<const EVP_MD*> hasher = EvpHashFromHashType(params.hash_type);
  ASSERT_THAT(hasher, IsOk());
  std::string data = absl::HexStringToBytes(params.data_hex);
  std::string expected_digest =
      absl::HexStringToBytes(params.expected_digest_hex);
  EXPECT_THAT(ComputeHash(data, **hasher), IsOkAndHolds(expected_digest));
}

INSTANTIATE_TEST_SUITE_P(MdUtilComputeHashSamplesTests,
                         MdUtilComputeHashSamplesTest,
                         ValuesIn(GetMdUtilComputeHashSamplesTestParams()));

}  // namespace
}  // namespace internal
}  // namespace tink
}  // namespace crypto
