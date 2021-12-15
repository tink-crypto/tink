// Copyright 2017 Google Inc.
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

#include "tink/subtle/subtle_util_boringssl.h"

#include <algorithm>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "openssl/cipher.h"
#include "openssl/curve25519.h"
#include "openssl/digest.h"
#include "openssl/ec.h"
#include "openssl/evp.h"
#include "openssl/nid.h"
#include "openssl/x509.h"
#include "include/rapidjson/document.h"
#include "tink/config/tink_fips.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/ec_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/subtle/common_enums.h"
#include "tink/subtle/wycheproof_util.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

static std::string GetError() {
  auto err = ERR_peek_last_error();
  // Sometimes there is no error message on the stack.
  if (err == 0) {
    return "";
  }
  std::string lib(ERR_lib_error_string(err));
  std::string func(ERR_func_error_string(err));
  std::string reason(ERR_reason_error_string(err));
  return lib + ":" + func + ":" + reason;
}

// Test with test vectors from Wycheproof project.
bool WycheproofTest(const rapidjson::Value& root) {
  int errors = 0;
  for (const rapidjson::Value& test_group : root["testGroups"].GetArray()) {
    std::string curve_str = test_group["curve"].GetString();
    // Tink only supports secp256r1, secp384r1 or secp521r1.
    if (!(curve_str == "secp256r1" || curve_str == "secp384r1" ||
          curve_str == "secp521r1")) {
      continue;
    }
    EllipticCurveType curve =
        WycheproofUtil::GetEllipticCurveType(test_group["curve"]);
    for (const rapidjson::Value& test : test_group["tests"].GetArray()) {
      std::string id = absl::StrCat(test["tcId"].GetInt());
      std::string comment = test["comment"].GetString();
      std::string pub_bytes = WycheproofUtil::GetBytes(test["public"]);
      std::string priv_bytes = WycheproofUtil::GetBytes(test["private"]);
      std::string expected_shared_bytes =
          WycheproofUtil::GetBytes(test["shared"]);
      std::string result = test["result"].GetString();
      EcPointFormat format = EcPointFormat::UNCOMPRESSED;
      for (const rapidjson::Value& flag : test["flags"].GetArray()) {
        if (std::string(flag.GetString()) == "CompressedPoint") {
          format = EcPointFormat::COMPRESSED;
        }
      }
      // Wycheproof's ECDH public key uses ASN encoding while Tink uses X9.62
      // format point encoding. For the purpose of testing, we note the
      // followings:
      //  + The prefix of ASN encoding contains curve name, so we can skip test
      //  vector with "UnnamedCurve".
      //  + The suffix of ASN encoding is X9.62 format point encoding.
      // TODO(quannguyen): Use X9.62 test vectors once it's available.
      bool skip = false;
      for (const rapidjson::Value& flag : test["flags"].GetArray()) {
        if (std::string(flag.GetString()) == "UnnamedCurve") {
          skip = true;
          break;
        }
      }
      if (skip) {
        continue;
      }
      util::StatusOr<int32_t> point_size =
          internal::EcPointEncodingSizeInBytes(curve, format);
      if (!point_size.ok()) {
        continue;
      }
      if (*point_size > pub_bytes.size()) {
        continue;
      }
      pub_bytes = pub_bytes.substr(pub_bytes.size() - *point_size, *point_size);
      auto status_or_ec_point =
          SubtleUtilBoringSSL::EcPointDecode(curve, format, pub_bytes);
      if (!status_or_ec_point.ok()) {
        if (result == "valid") {
          ADD_FAILURE() << "Could not decode public key with tcId:" << id
                        << " error:" << GetError()
                        << status_or_ec_point.status();
        }
        continue;
      }
      internal::SslUniquePtr<EC_POINT> pub_key =
          std::move(status_or_ec_point.ValueOrDie());
      internal::SslUniquePtr<BIGNUM> priv_key(
          BN_bin2bn(reinterpret_cast<const unsigned char*>(priv_bytes.data()),
                    priv_bytes.size(), nullptr));
      auto status_or_shared = SubtleUtilBoringSSL ::ComputeEcdhSharedSecret(
          curve, priv_key.get(), pub_key.get());
      if (status_or_shared.ok()) {
        util::SecretData shared = status_or_shared.ValueOrDie();
        if (result == "invalid") {
          ADD_FAILURE() << "Computed shared secret with invalid test vector"
                        << ", tcId= " << id;
          errors++;
        } else if (util::SecretDataAsStringView(shared) !=
                   expected_shared_bytes) {
          ADD_FAILURE() << "Computed wrong shared secret with tcId: " << id;
          errors++;
        }
      } else {
        if (result == "valid" || result == "acceptable") {
          ADD_FAILURE() << "Could not compute shared secret with tcId:" << id;
          errors++;
        }
      }
    }
  }
  return errors == 0;
}

TEST(SubtleUtilBoringSSLTest, ComputeEcdhSharedSecretWithWycheproofTest) {
// placeholder_disabled_subtle_test, please ignore
  ASSERT_TRUE(WycheproofTest(
      *WycheproofUtil ::ReadTestVectors("ecdh_test.json")));
  ASSERT_TRUE(WycheproofTest(
      *WycheproofUtil ::ReadTestVectors("ecdh_secp256r1_test.json")));
  ASSERT_TRUE(WycheproofTest(
      *WycheproofUtil ::ReadTestVectors("ecdh_secp384r1_test.json")));
  ASSERT_TRUE(WycheproofTest(
      *WycheproofUtil ::ReadTestVectors("ecdh_secp521r1_test.json")));
}

TEST(CreatesNewEd25519KeyPairTest, BoringSSLPrivateKeySuffix) {
  // Generate a new key pair.
  uint8_t out_public_key[ED25519_PUBLIC_KEY_LEN];
  uint8_t out_private_key[ED25519_PRIVATE_KEY_LEN];

  ED25519_keypair(out_public_key, out_private_key);
  std::string pk = std::string(reinterpret_cast<const char*>(out_public_key),
                               ED25519_PUBLIC_KEY_LEN);
  std::string sk = std::string(reinterpret_cast<const char*>(out_private_key),
                               ED25519_PRIVATE_KEY_LEN);
  ASSERT_EQ(pk.length(), 32);
  ASSERT_EQ(sk.length(), 64);
  // BoringSSL's ED25519_keypair returns a private key with the last 32-bytes
  // equal to the public key. If this changes you must update
  // SubtleUtilBoringSSL::GetNewEd25519Key().
  ASSERT_EQ(sk.substr(32, std::string::npos), pk);
}

TEST(SublteUtilBoringSSLTest, GetCipherForKeySize) {
  EXPECT_EQ(SubtleUtilBoringSSL::GetAesCtrCipherForKeySize(16),
            EVP_aes_128_ctr());
  EXPECT_EQ(SubtleUtilBoringSSL::GetAesCtrCipherForKeySize(32),
            EVP_aes_256_ctr());
  EXPECT_EQ(SubtleUtilBoringSSL::GetAesCtrCipherForKeySize(64), nullptr);
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
