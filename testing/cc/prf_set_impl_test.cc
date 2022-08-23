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

#include "prf_set_impl.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/binary_keyset_writer.h"
#include "tink/cleartext_keyset_handle.h"
#include "tink/prf/prf_config.h"
#include "tink/prf/prf_key_templates.h"
#include "proto/testing_api.grpc.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::BinaryKeysetWriter;
using ::crypto::tink::CleartextKeysetHandle;
using ::crypto::tink::PrfKeyTemplates;

using ::testing::ElementsAre;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::tink_testing_api::CreationRequest;
using ::tink_testing_api::CreationResponse;
using ::tink_testing_api::PrfSetComputeRequest;
using ::tink_testing_api::PrfSetComputeResponse;
using ::tink_testing_api::PrfSetKeyIdsRequest;
using ::tink_testing_api::PrfSetKeyIdsResponse;

using crypto::tink::KeysetHandle;
using google::crypto::tink::KeyTemplate;

std::string ValidKeyset() {
  const KeyTemplate& key_template = PrfKeyTemplates::HmacSha256();
  auto handle_result = KeysetHandle::GenerateNew(key_template);
  EXPECT_TRUE(handle_result.ok());
  std::stringbuf keyset;
  auto writer_result =
      BinaryKeysetWriter::New(absl::make_unique<std::ostream>(&keyset));
  EXPECT_TRUE(writer_result.ok());

  auto status = CleartextKeysetHandle::Write(writer_result.value().get(),
                                             *handle_result.value());
  EXPECT_TRUE(status.ok());
  return keyset.str();
}

class PrfSetImplTest : public ::testing::Test {
 protected:
  static void SetUpTestSuite() { ASSERT_TRUE(PrfConfig::Register().ok()); }
};

TEST_F(PrfSetImplTest, CreateAeadSuccess) {
  tink_testing_api::PrfSetImpl prfset;
  std::string keyset = ValidKeyset();
  CreationRequest request;
  request.set_keyset(keyset);
  CreationResponse response;

  EXPECT_TRUE(prfset.Create(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), IsEmpty());
}

TEST_F(PrfSetImplTest, CreateAeadFails) {
  tink_testing_api::PrfSetImpl prfset;
  CreationRequest request;
  request.set_keyset("bad keyset");
  CreationResponse response;

  EXPECT_TRUE(prfset.Create(nullptr, &request, &response).ok());
  EXPECT_THAT(response.err(), Not(IsEmpty()));
}

TEST_F(PrfSetImplTest, KeyIdsComputeSuccess) {
  tink_testing_api::PrfSetImpl prfset;
  std::string keyset = ValidKeyset();

  PrfSetKeyIdsRequest key_id_request;
  key_id_request.set_keyset(keyset);
  PrfSetKeyIdsResponse key_id_response;

  EXPECT_TRUE(prfset.KeyIds(nullptr, &key_id_request, &key_id_response).ok());
  EXPECT_THAT(key_id_response.err(), IsEmpty());
  EXPECT_THAT(key_id_response.output().key_id(),
              ElementsAre(key_id_response.output().primary_key_id()));

  PrfSetComputeRequest comp_request;
  comp_request.set_keyset(keyset);
  comp_request.set_key_id(key_id_response.output().primary_key_id());
  comp_request.set_input_data("some data");
  comp_request.set_output_length(16);
  PrfSetComputeResponse comp_response;

  EXPECT_TRUE(prfset.Compute(nullptr, &comp_request, &comp_response).ok());
  EXPECT_THAT(comp_response.err(), IsEmpty());
  EXPECT_THAT(comp_response.output().size(), Eq(16));
}

TEST_F(PrfSetImplTest, KeyIdsBadKeysetFail) {
  tink_testing_api::PrfSetImpl prfset;
  PrfSetKeyIdsRequest key_id_request;
  key_id_request.set_keyset("bad keyset");
  PrfSetKeyIdsResponse key_id_response;

  EXPECT_TRUE(prfset.KeyIds(nullptr, &key_id_request, &key_id_response).ok());
  EXPECT_THAT(key_id_response.err(), Not(IsEmpty()));
}

TEST_F(PrfSetImplTest, ComputeBadKeysetFail) {
  tink_testing_api::PrfSetImpl prfset;
  PrfSetComputeRequest comp_request;
  comp_request.set_keyset("bad keyset");
  comp_request.set_key_id(1234);
  comp_request.set_input_data("some data");
  comp_request.set_output_length(16);
  PrfSetComputeResponse comp_response;

  EXPECT_TRUE(prfset.Compute(nullptr, &comp_request, &comp_response).ok());
  EXPECT_THAT(comp_response.err(), Not(IsEmpty()));
}

TEST_F(PrfSetImplTest, ComputeBadOutputLengthFail) {
  tink_testing_api::PrfSetImpl prfset;
  std::string keyset = ValidKeyset();
  PrfSetKeyIdsRequest key_id_request;
  key_id_request.set_keyset(keyset);
  PrfSetKeyIdsResponse key_id_response;
  EXPECT_TRUE(prfset.KeyIds(nullptr, &key_id_request, &key_id_response).ok());
  EXPECT_THAT(key_id_response.err(), IsEmpty());

  PrfSetComputeRequest comp_request;
  comp_request.set_keyset(keyset);
  comp_request.set_key_id(key_id_response.output().primary_key_id());
  comp_request.set_input_data("some data");
  comp_request.set_output_length(123456);  // bad output length
  PrfSetComputeResponse comp_response;
  EXPECT_TRUE(prfset.Compute(nullptr, &comp_request, &comp_response).ok());
  EXPECT_THAT(comp_response.err(), Not(IsEmpty()));
}

TEST_F(PrfSetImplTest, ComputeBadKeyIdFail) {
  tink_testing_api::PrfSetImpl prfset;
  std::string keyset = ValidKeyset();

  PrfSetComputeRequest comp_request;
  comp_request.set_keyset(keyset);
  comp_request.set_key_id(12345);  // bad key id
  comp_request.set_input_data("some data");
  comp_request.set_output_length(16);
  PrfSetComputeResponse comp_response;
  EXPECT_TRUE(prfset.Compute(nullptr, &comp_request, &comp_response).ok());
  EXPECT_THAT(comp_response.err(), Not(IsEmpty()));
}

}  // namespace
}  // namespace tink
}  // namespace crypto
