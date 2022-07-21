// Copyright 2020 Google LLC
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

#include "metadata_impl.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "proto/testing_api.grpc.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::testing::Eq;
using ::testing::IsEmpty;
using tink_testing_api::ServerInfoRequest;
using tink_testing_api::ServerInfoResponse;

TEST(MetadataImplTest, GetServerInfo) {
  tink_testing_api::MetadataImpl metadata;
  ServerInfoRequest request;
  ServerInfoResponse response;
  EXPECT_TRUE(metadata.GetServerInfo(nullptr, &request, &response).ok());
  EXPECT_THAT(response.language(), Eq("cc"));
  EXPECT_THAT(response.tink_version(), Not(IsEmpty()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
