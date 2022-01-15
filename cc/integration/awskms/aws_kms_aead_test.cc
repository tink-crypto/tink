// Copyright 2018 Google LLC
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

#include "tink/integration/awskms/aws_kms_aead.h"

#include <string>
#include <vector>

#include "absl/strings/str_cat.h"
#include "aws/core/Aws.h"
#include "aws/kms/KMSClient.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "gtest/gtest.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using crypto::tink::integration::awskms::AwsKmsAead;

class AwsKmsAeadTest : public ::testing::Test {
  // TODO(przydatek): add a test with a mock KMSClient.
};


}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
