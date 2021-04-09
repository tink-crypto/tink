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

#include "gtest/gtest.h"
#include "tink/integration/gcpkms/gcp_kms_aead.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using crypto::tink::integration::gcpkms::GcpKmsAead;

class GcpKmsAeadTest : public ::testing::Test {
  // TODO(kste): Add tests when mock for
  // google::cloud::kms::v1::KeyManagementService::StubInterface is available.
};


}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
