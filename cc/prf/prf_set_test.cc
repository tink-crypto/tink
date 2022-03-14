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

#include "tink/prf/prf_set.h"

#include <map>
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "tink/keyset_handle.h"
#include "tink/keyset_manager.h"
#include "tink/prf/prf_config.h"
#include "tink/prf/prf_key_templates.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::testing::_;
using ::testing::Eq;
using ::testing::Pair;
using ::testing::SizeIs;
using ::testing::StrEq;
using ::testing::UnorderedElementsAre;

class DummyPrf : public Prf {
  util::StatusOr<std::string> Compute(absl::string_view input,
                                      size_t output_length) const override {
    return std::string("DummyPRF");
  }
};

class DummyPrfSet : public PrfSet {
 public:
  uint32_t GetPrimaryId() const override { return 1; }
  const std::map<uint32_t, Prf*>& GetPrfs() const override {
    static const std::map<uint32_t, Prf*>* prfs =
        new std::map<uint32_t, Prf*>({{1, dummy_.get()}});
    return *prfs;
  }

 private:
  std::unique_ptr<Prf> dummy_ = absl::make_unique<DummyPrf>();
};

class BrokenDummyPrfSet : public PrfSet {
 public:
  uint32_t GetPrimaryId() const override { return 1; }
  const std::map<uint32_t, Prf*>& GetPrfs() const override {
    static const std::map<uint32_t, Prf*>* prfs =
        new std::map<uint32_t, Prf*>();
    return *prfs;
  }
};

TEST(PrfSetTest, ComputePrimary) {
  DummyPrfSet prfset;
  auto output = prfset.ComputePrimary("DummyInput", 16);
  EXPECT_TRUE(output.ok()) << output.status();
  BrokenDummyPrfSet broken_prfset;
  auto broken_output = broken_prfset.ComputePrimary("DummyInput", 16);
  EXPECT_FALSE(broken_output.ok())
      << "Expected broken PrfSet to not be able to compute the primary PRF";
}

TEST(PrfSetWrapperTest, TestPrimitivesEndToEnd) {
  auto status = PrfConfig::Register();
  ASSERT_TRUE(status.ok()) << status;
  auto keyset_manager_result =
      KeysetManager::New(PrfKeyTemplates::HkdfSha256());
  ASSERT_TRUE(keyset_manager_result.ok()) << keyset_manager_result.status();
  auto keyset_manager = std::move(keyset_manager_result.ValueOrDie());
  auto id_result = keyset_manager->Add(PrfKeyTemplates::HmacSha256());
  ASSERT_TRUE(id_result.ok()) << id_result.status();
  uint32_t hmac_sha256_id = id_result.ValueOrDie();
  id_result = keyset_manager->Add(PrfKeyTemplates::HmacSha512());
  ASSERT_TRUE(id_result.ok()) << id_result.status();
  uint32_t hmac_sha512_id = id_result.ValueOrDie();
  id_result = keyset_manager->Add(PrfKeyTemplates::AesCmac());
  ASSERT_TRUE(id_result.ok()) << id_result.status();
  uint32_t aes_cmac_id = id_result.ValueOrDie();
  auto keyset_handle = keyset_manager->GetKeysetHandle();
  uint32_t hkdf_id = keyset_handle->GetKeysetInfo().primary_key_id();
  auto prf_set_result = keyset_handle->GetPrimitive<PrfSet>();
  ASSERT_TRUE(prf_set_result.ok()) << prf_set_result.status();
  auto prf_set = std::move(prf_set_result.ValueOrDie());
  EXPECT_THAT(prf_set->GetPrimaryId(), Eq(hkdf_id));
  auto prf_map = prf_set->GetPrfs();
  EXPECT_THAT(prf_map, UnorderedElementsAre(Pair(Eq(hkdf_id), _),
                                            Pair(Eq(hmac_sha256_id), _),
                                            Pair(Eq(hmac_sha512_id), _),
                                            Pair(Eq(aes_cmac_id), _)));
  std::string input = "This is an input string";
  std::string input2 = "This is a second input string";
  std::vector<size_t> output_lengths = {15, 16, 17, 31, 32,
                                        33, 63, 64, 65, 100};
  for (size_t output_length : output_lengths) {
    bool aes_cmac_ok = output_length <= 16;
    bool hmac_sha256_ok = output_length <= 32;
    bool hmac_sha512_ok = output_length <= 64;
    bool hkdf_sha256_ok = output_length <= 8192;
    std::vector<std::string> results;
    for (auto prf : prf_map) {
      SCOPED_TRACE(absl::StrCat("Computing prf ", prf.first,
                                " with output_length ", output_length));
      bool ok = (prf.first == aes_cmac_id && aes_cmac_ok) ||
                (prf.first == hmac_sha256_id && hmac_sha256_ok) ||
                (prf.first == hmac_sha512_id && hmac_sha512_ok) ||
                (prf.first == hkdf_id && hkdf_sha256_ok);
      auto output_result = prf.second->Compute(input, output_length);
      EXPECT_THAT(output_result.ok(), Eq(ok)) << output_result.status();
      if (!ok) {
        continue;
      }
      std::string output;
      if (output_result.ok()) {
        output = output_result.ValueOrDie();
        results.push_back(output);
      }
      output_result = prf.second->Compute(input2, output_length);
      EXPECT_TRUE(output_result.ok()) << output_result.status();
      if (output_result.ok()) {
        results.push_back(output_result.ValueOrDie());
      }
      output_result = prf.second->Compute(input, output_length);
      EXPECT_TRUE(output_result.ok()) << output_result.status();
      if (output_result.ok()) {
        EXPECT_THAT(output_result.ValueOrDie(), StrEq(output));
      }
    }
    for (int i = 0; i < results.size(); i++) {
      EXPECT_THAT(results[i], SizeIs(output_length));
      EXPECT_THAT(test::ZTestUniformString(results[i]), IsOk());
      EXPECT_THAT(test::ZTestAutocorrelationUniformString(results[i]), IsOk());
      for (int j = i + 1; j < results.size(); j++) {
        EXPECT_THAT(
            test::ZTestCrosscorrelationUniformStrings(results[i], results[j]),
            IsOk());
      }
    }
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
