// Copyright 2023 Google LLC
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

#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "tink/integration/awskms/aws_kms_aead.h"
#include "tink/integration/awskms/aws_kms_client.h"
#include "tink/integration/awskms/internal/test_file_util.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace integration {
namespace awskms {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::IsOkAndHolds;

constexpr absl::string_view kAwsKmsKeyUri =
    "aws-kms://arn:aws:kms:us-east-2:235739564943:key/"
    "3ee50705-5a82-4f5b-9753-05c4f473922f";

TEST(AwsKmsAeadTest, EncryptDecrypt) {
  std::string credentials =
      internal::RunfilesPath("testdata/aws/credentials.ini");
  util::StatusOr<std::unique_ptr<AwsKmsClient>> client =
      AwsKmsClient::New(/*key_uri=*/"", credentials);
  ASSERT_THAT(client, IsOk());

  util::StatusOr<std::unique_ptr<Aead>> aead =
      (*client)->GetAead(kAwsKmsKeyUri);
  ASSERT_THAT(aead, IsOk());

  constexpr absl::string_view kPlaintext = "plaintext";
  constexpr absl::string_view kAssociatedData = "aad";

  util::StatusOr<std::string> ciphertext =
      (*aead)->Encrypt(kPlaintext, kAssociatedData);
  ASSERT_THAT(ciphertext, IsOk());
  EXPECT_THAT((*aead)->Decrypt(*ciphertext, kAssociatedData),
              IsOkAndHolds(kPlaintext));
}
}  // namespace
}  // namespace awskms
}  // namespace integration
}  // namespace tink
}  // namespace crypto
