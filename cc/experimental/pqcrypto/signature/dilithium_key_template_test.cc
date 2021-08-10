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

#include "tink/experimental/pqcrypto/signature/dilithium_key_template.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/core/key_manager_impl.h"
#include "tink/core/private_key_manager_impl.h"
#include "tink/experimental/pqcrypto/signature/dilithium_sign_key_manager.h"
#include "tink/experimental/pqcrypto/signature/dilithium_verify_key_manager.h"
#include "tink/util/test_matchers.h"
#include "proto/tink.pb.h"

namespace crypto {
namespace tink {
namespace {

using ::crypto::tink::test::IsOk;
using ::google::crypto::tink::DilithiumKeyFormat;
using ::google::crypto::tink::DilithiumPrivateKey;
using ::google::crypto::tink::KeyTemplate;
using ::google::crypto::tink::OutputPrefixType;

TEST(DilithiumKeyTemplateTest, CheckInitialization) {
  std::string type_url =
      "type.googleapis.com/google.crypto.tink.DilithiumPrivateKey";
  const KeyTemplate& key_template = DilithiumKeyTemplate();

  EXPECT_EQ(type_url, key_template.type_url());
  EXPECT_EQ(OutputPrefixType::TINK, key_template.output_prefix_type());
}

TEST(DilithiumKeyTemplateTest, ValidateKeyFormat) {
  const KeyTemplate& key_template = DilithiumKeyTemplate();
  DilithiumKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  EXPECT_THAT(DilithiumSignKeyManager().ValidateKeyFormat(key_format), IsOk());
}

TEST(DilithiumKeyTemplateTest, SameReference) {
  const KeyTemplate& key_template = DilithiumKeyTemplate();
  const KeyTemplate& key_template_2 = DilithiumKeyTemplate();

  EXPECT_EQ(&key_template, &key_template_2);
}

TEST(DilithiumKeyTemplateTest, KeyManagerCompatibility) {
  const KeyTemplate& key_template = DilithiumKeyTemplate();

  DilithiumSignKeyManager sign_key_manager;
  DilithiumVerifyKeyManager verify_key_manager;
  std::unique_ptr<KeyManager<PublicKeySign>> key_manager =
      internal::MakePrivateKeyManager<PublicKeySign>(&sign_key_manager,
                                                     &verify_key_manager);
  EXPECT_EQ(key_manager->get_key_type(), key_template.type_url());

  DilithiumKeyFormat key_format;
  EXPECT_TRUE(key_format.ParseFromString(key_template.value()));
  util::StatusOr<std::unique_ptr<portable_proto::MessageLite>> new_key_result =
      key_manager->get_key_factory().NewKey(key_format);
  EXPECT_THAT(new_key_result.status(), IsOk());
}

}  // namespace
}  // namespace tink
}  // namespace crypto
