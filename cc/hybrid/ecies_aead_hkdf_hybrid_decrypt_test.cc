// Copyright 2017 Google LLC
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

#include "tink/hybrid/ecies_aead_hkdf_hybrid_decrypt.h"

#include "gtest/gtest.h"
#include "absl/memory/memory.h"
#include "tink/aead/aes_ctr_hmac_aead_key_manager.h"
#include "tink/aead/aes_gcm_key_manager.h"
#include "tink/aead/xchacha20_poly1305_key_manager.h"
#include "tink/daead/aes_siv_key_manager.h"
#include "tink/hybrid/ecies_aead_hkdf_hybrid_encrypt.h"
#include "tink/hybrid_decrypt.h"
#include "tink/internal/ec_util.h"
#include "tink/registry.h"
#include "tink/subtle/random.h"
#include "tink/util/enums.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"
#include "proto/aes_gcm.pb.h"
#include "proto/common.pb.h"
#include "proto/ecies_aead_hkdf.pb.h"

using crypto::tink::subtle::Random;
using ::crypto::tink::test::IsOkAndHolds;
using google::crypto::tink::EciesAeadHkdfPrivateKey;
using google::crypto::tink::EcPointFormat;
using google::crypto::tink::EllipticCurveType;
using google::crypto::tink::HashType;
using ::testing::Eq;

namespace crypto {
namespace tink {
namespace {

class EciesAeadHkdfHybridDecryptTest : public ::testing::Test {
 protected:
  void SetUp() override {}
  void TearDown() override {}

  struct CommonHybridKeyParams {
    EllipticCurveType ec_curve;
    EcPointFormat ec_point_format;
    HashType hash_type;
  };

  std::vector<CommonHybridKeyParams> GetCommonHybridKeyParamsList() {
    std::vector<CommonHybridKeyParams> params_list;
    for (auto ec_curve :
         {EllipticCurveType::NIST_P256, EllipticCurveType::NIST_P384,
          EllipticCurveType::NIST_P521, EllipticCurveType::CURVE25519}) {
      for (auto ec_point_format :
           {EcPointFormat::UNCOMPRESSED, EcPointFormat::COMPRESSED}) {
        if (ec_curve == EllipticCurveType::CURVE25519 &&
            ec_point_format == EcPointFormat::UNCOMPRESSED) {
          continue;
        }
        for (auto hash_type : {HashType::SHA256, HashType::SHA512}) {
          CommonHybridKeyParams params;
          params.ec_curve = ec_curve;
          params.ec_point_format = ec_point_format;
          params.hash_type = hash_type;
          params_list.push_back(params);
        }
      }
    }
    return params_list;
  }

  EciesAeadHkdfPrivateKey GetEciesPrivateKeyFromHexString(
      absl::string_view private_key_hex_string,
      CommonHybridKeyParams& key_params) {
    auto ecies_key = test::GetEciesAesSivHkdfTestKey(
        key_params.ec_curve, key_params.ec_point_format, key_params.hash_type);
    ecies_key.set_key_value(test::HexDecodeOrDie(private_key_hex_string));
    return ecies_key;
  }

  void TestValidKey(const EciesAeadHkdfPrivateKey& ecies_key) {
    auto result(EciesAeadHkdfHybridDecrypt::New(ecies_key));
    ASSERT_TRUE(result.ok()) << result.status() << ecies_key.DebugString();
    std::unique_ptr<HybridDecrypt> hybrid_decrypt(
        std::move(result.ValueOrDie()));

    std::unique_ptr<HybridEncrypt> hybrid_encrypt(std::move(
        EciesAeadHkdfHybridEncrypt::New(ecies_key.public_key()).ValueOrDie()));

    std::string context_info = "some context info";
    for (uint32_t plaintext_size : {0, 1, 10, 100, 1000}) {
      // Use the primitive.
      std::string plaintext = Random::GetRandomBytes(plaintext_size);
      auto ciphertext =
          hybrid_encrypt->Encrypt(plaintext, context_info).ValueOrDie();
      {  // Regular decryption.
        auto decrypt_result = hybrid_decrypt->Decrypt(ciphertext, context_info);
        EXPECT_TRUE(decrypt_result.ok()) << decrypt_result.status();
        EXPECT_EQ(plaintext, decrypt_result.ValueOrDie());
      }
      {  // Encryption and decryption with empty context info.
        const absl::string_view empty_context_info;
        auto ciphertext =
            hybrid_encrypt->Encrypt(plaintext, empty_context_info).ValueOrDie();
        auto decrypt_result =
            hybrid_decrypt->Decrypt(ciphertext, empty_context_info);
        ASSERT_TRUE(decrypt_result.ok()) << decrypt_result.status();
        EXPECT_EQ(plaintext, decrypt_result.ValueOrDie());
      }
      {  // Encryption and decryption w/ empty msg & context info.
        const absl::string_view empty_plaintext;
        const absl::string_view empty_context_info;
        auto ciphertext =
            hybrid_encrypt->Encrypt(empty_plaintext, empty_context_info)
                .ValueOrDie();
        auto decrypt_result =
            hybrid_decrypt->Decrypt(ciphertext, empty_context_info);
        ASSERT_TRUE(decrypt_result.ok()) << decrypt_result.status();
        EXPECT_EQ(empty_plaintext, decrypt_result.ValueOrDie());
      }
      {  // Short bad ciphertext.
        auto decrypt_result =
            hybrid_decrypt->Decrypt(Random::GetRandomBytes(16), context_info);
        EXPECT_FALSE(decrypt_result.ok());
        EXPECT_EQ(absl::StatusCode::kInvalidArgument,
                  decrypt_result.status().code());
        EXPECT_PRED_FORMAT2(testing::IsSubstring, "ciphertext too short",
                            std::string(decrypt_result.status().message()));
      }
      {  // Long but still bad ciphertext.
        auto decrypt_result =
            hybrid_decrypt->Decrypt(Random::GetRandomBytes(142), context_info);
        EXPECT_FALSE(decrypt_result.ok());
        // TODO(przydatek): add more checks while avoiding flakiness.
      }
      {  // Bad context info
        auto decrypt_result =
            hybrid_decrypt->Decrypt(ciphertext, Random::GetRandomBytes(14));
        EXPECT_FALSE(decrypt_result.ok());
      }
    }
  }
};

TEST_F(EciesAeadHkdfHybridDecryptTest, testInvalidKeys) {
  {  // No fields set.
    EciesAeadHkdfPrivateKey recipient_key;
    auto result = EciesAeadHkdfHybridDecrypt::New(recipient_key);
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "missing required fields",
                        std::string(result.status().message()));
  }

  {  // Only some fields set.
    EciesAeadHkdfPrivateKey recipient_key;
    recipient_key.set_version(0);
    recipient_key.mutable_public_key()->set_x("some x bytes");
    recipient_key.mutable_public_key()->set_y("some y bytes");
    auto result(EciesAeadHkdfHybridDecrypt::New(recipient_key));
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "missing required fields",
                        std::string(result.status().message()));
  }

  {  // Wrong EC type.
    EciesAeadHkdfPrivateKey recipient_key;
    recipient_key.set_version(0);
    recipient_key.set_key_value("some key value bytes");
    recipient_key.mutable_public_key()->set_x("some x bytes");
    recipient_key.mutable_public_key()->set_y("some y bytes");
    recipient_key.mutable_public_key()->mutable_params();
    auto result(EciesAeadHkdfHybridDecrypt::New(recipient_key));
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(absl::StatusCode::kUnimplemented, result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "Unsupported elliptic curve",
                        std::string(result.status().message()));
  }

  {  // Unsupported DEM key type.
    EllipticCurveType curve = EllipticCurveType::NIST_P256;
    auto test_key =
        internal::NewEcKey(util::Enums::ProtoToSubtle(curve)).ValueOrDie();
    EciesAeadHkdfPrivateKey recipient_key;
    recipient_key.set_version(0);
    recipient_key.set_key_value("some key value bytes");
    recipient_key.mutable_public_key()->set_x(test_key.pub_x);
    recipient_key.mutable_public_key()->set_y(test_key.pub_y);
    auto params = recipient_key.mutable_public_key()->mutable_params();
    params->mutable_kem_params()->set_curve_type(curve);
    params->mutable_kem_params()->set_hkdf_hash_type(HashType::SHA256);
    auto aead_dem = params->mutable_dem_params()->mutable_aead_dem();
    aead_dem->set_type_url("some.type.url/that.is.not.supported");
    auto result(EciesAeadHkdfHybridDecrypt::New(recipient_key));
    EXPECT_FALSE(result.ok());
    EXPECT_EQ(absl::StatusCode::kInvalidArgument, result.status().code());
    EXPECT_PRED_FORMAT2(testing::IsSubstring, "Unsupported DEM",
                        std::string(result.status().message()));
  }
}

TEST_F(EciesAeadHkdfHybridDecryptTest, testGettingHybridEncryptWithoutManager) {
  // Prepare an ECIES key.
  Registry::Reset();
  auto ecies_key = test::GetEciesAesGcmHkdfTestKey(EllipticCurveType::NIST_P256,
                                                   EcPointFormat::UNCOMPRESSED,
                                                   HashType::SHA256, 32);

  // Try to get a HybridEncrypt primitive without DEM key manager.
  auto bad_result(EciesAeadHkdfHybridDecrypt::New(ecies_key));
  EXPECT_FALSE(bad_result.ok());
  EXPECT_EQ(absl::StatusCode::kFailedPrecondition, bad_result.status().code());
  EXPECT_PRED_FORMAT2(testing::IsSubstring, "No manager for DEM",
                      std::string(bad_result.status().message()));
}

TEST_F(EciesAeadHkdfHybridDecryptTest, testAesGcmHybridDecryption) {
  // Register DEM key manager.
  std::string dem_key_type = AesGcmKeyManager().get_key_type();
  ASSERT_TRUE(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesGcmKeyManager>(), true)
                  .ok());

  int i = 0;
  // Generate and test many keys with various parameters.
  for (auto key_params : GetCommonHybridKeyParamsList()) {
    for (uint32_t aes_gcm_key_size : {16, 32}) {
      ++i;
      auto ecies_key = test::GetEciesAesGcmHkdfTestKey(
          key_params.ec_curve, key_params.ec_point_format, key_params.hash_type,
          aes_gcm_key_size);
      TestValidKey(ecies_key);
    }
  }
  EXPECT_EQ(i, 32 - 4);
}

TEST_F(EciesAeadHkdfHybridDecryptTest, testAesCtrAeadHybridDecryption) {
  // Register DEM key manager.
  std::string dem_key_type = AesCtrHmacAeadKeyManager().get_key_type();
  ASSERT_TRUE(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesCtrHmacAeadKeyManager>(), true)
                  .ok());

  uint32_t aes_ctr_iv_size = 16;
  // Generate and test many keys with various parameters.
  for (auto key_params : GetCommonHybridKeyParamsList()) {
    for (uint32_t aes_ctr_key_size : {16, 32}) {
      for (auto hmac_hash_type : {HashType::SHA256, HashType::SHA512}) {
        for (uint32_t hmac_tag_size : {16, 32}) {
          for (uint32_t hmac_key_size : {16, 32}) {
            auto ecies_key = test::GetEciesAesCtrHmacHkdfTestKey(
                key_params.ec_curve, key_params.ec_point_format,
                key_params.hash_type, aes_ctr_key_size, aes_ctr_iv_size,
                hmac_hash_type, hmac_tag_size, hmac_key_size);
            TestValidKey(ecies_key);
          }
        }
      }
    }
  }
}

TEST_F(EciesAeadHkdfHybridDecryptTest, testXChaCha20Poly1305HybridDecryption) {
  // Register DEM key manager.
  std::string dem_key_type = XChaCha20Poly1305KeyManager().get_key_type();
  ASSERT_TRUE(Registry::RegisterKeyTypeManager(
                  absl::make_unique<XChaCha20Poly1305KeyManager>(), true)
                  .ok());

  // Generate and test many keys with various parameters.
  for (auto key_params : GetCommonHybridKeyParamsList()) {
    auto ecies_key = test::GetEciesXChaCha20Poly1305HkdfTestKey(
        key_params.ec_curve, key_params.ec_point_format, key_params.hash_type);
    TestValidKey(ecies_key);
  }
}

TEST_F(EciesAeadHkdfHybridDecryptTest, testAesSivHybridDecryption) {
  // Register DEM key manager.
  std::string dem_key_type = AesSivKeyManager().get_key_type();
  ASSERT_TRUE(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesSivKeyManager>(), true)
                  .ok());

  // Generate and test many keys with various parameters.
  for (auto key_params : GetCommonHybridKeyParamsList()) {
    auto ecies_key = test::GetEciesAesSivHkdfTestKey(
        key_params.ec_curve, key_params.ec_point_format, key_params.hash_type);
    TestValidKey(ecies_key);
  }
}

struct TestVector {
  EciesAeadHkdfPrivateKey private_key;
  std::string ciphertext;
  std::string context_info;
  std::string plaintext;
};

TEST_F(EciesAeadHkdfHybridDecryptTest,
       testAesSivHybridDecryptionWithTestVectors) {
  // Register DEM key manager.
  std::string dem_key_type = AesSivKeyManager().get_key_type();
  ASSERT_TRUE(Registry::RegisterKeyTypeManager(
                  absl::make_unique<AesSivKeyManager>(), true)
                  .ok());

  CommonHybridKeyParams key_params = {EllipticCurveType::NIST_P256,
                                      EcPointFormat::UNCOMPRESSED,
                                      HashType::SHA256};
  TestVector hybrid_decryption_test_vectors[] = {
      {
          /*TEST 1*/
          /*private_key=*/
          GetEciesPrivateKeyFromHexString("32588172ed65830571bb83748f7fddd38332"
                                          "3208a7825c80a71bef846333eb02",
                                          key_params),
          /*ciphertext=*/
          test::HexDecodeOrDie(
              "0401b11f8c9bafe30ae13f8bd15528714e752631a4328bf146009068e99489c8"
              "e9fae1ec39e3fe9994723711417fcab2af4b3c9b60117d47d33d35175c87b483"
              "b8935a73312940d1fbf8da3944a89b5e8b"),
          /*context_info=*/
          "some context info",
          /*plaintext=*/"",
      },
      {
          /*TEST 2*/
          /*private_key=*/
          GetEciesPrivateKeyFromHexString("32588172ed65830571bb83748f7fddd38332"
                                          "3208a7825c80a71bef846333eb02",
                                          key_params),
          /*ciphertext=*/
          test::HexDecodeOrDie(
              "040230023d1547b55af5a735a7f460722612126d7539d7cd0f677d308b29c6f5"
              "2a964e66e7b0cb44cff1673df9e2c793f1477ca755807bfbeadcae1ab20b45ec"
              "b1501ca5e3f5b0626d3ca40aa5d010443d506e4df90b"),
          /*context_info=*/
          "some context info",
          /*plaintext=*/"hello",
      },
      {
          /*TEST 3*/
          /*private_key=*/
          GetEciesPrivateKeyFromHexString("32588172ed65830571bb83748f7fddd38332"
                                          "3208a7825c80a71bef846333eb02",
                                          key_params),
          /*ciphertext=*/
          test::HexDecodeOrDie(
              "0441ddd246cea0825bd68bddff05cec54a4ee678da35b2f5cfbbb32e5350bdd8"
              "17214bfb7b5ed5528131bde56916062cfbd8b9952d9e0907a6e87e1de54db5df"
              "3aaccddd328efcf7771ce061e647488f66b8c11a9fca171dcff813e90b44b273"
              "9573f9f23b60202491870c7ff8aaf0ae46838e48f17f8dc1ad55b67809699dd3"
              "1eb6ca50dfa9beeee32d30bdc00a1eb1d8b0cbcedbe50b1e24619cc5e79042f2"
              "5f49e2c2d5a35c79e833c0d68e31a93da4173aacd0428b367594ed4636763d16"
              "c23e4f8c115d44bddc83bcefcaea13587238ce8b7a5d5fad53beeb59aaa1d748"
              "3eb4bac93ed50ed4d3e9fd5af760283fd38080b58744b73212a36039179ce6f9"
              "6ef1ecaa05b5186967d81c06b9cd91140dfbd54084ddcfd941527719848a2eec"
              "b84278f6a0fe9357a3964f87222fcd16a12a353e1f64fd45dc227a4a2112da6f"
              "61269f22f16b41e68eadf0b6b3a48c67b9e7e3ec1c66eecce50dda8ecbce99d3"
              "778299aa28741b7247fbc46a1b8a908dc23943c2dd17210a270bb12b096c2c6a"
              "00400a95c62894a15b9fc44e709d27348f2f2644a786cd9e96caf42ea9b949f7"
              "6e85e6f7365e15fa2902e851222c025f6c208269d799fcfc4c0b37aba8979ed9"
              "e6ccf543c217ee0b6ad05f0e3ffb92943d308c801b25efedab5bf93a733bdae6"
              "11132d774d4b9ee4fb5e88ae63014315ae9571039a8c8c7020e2b3a1bbd4235b"
              "65af94771c8417c87fd6cab423b82a557f60a99ae7402dba205e05136dd34f00"
              "26fce87899d4b9819cc2b2ba686512d62c41a1e3a667a705ea45404aafa489cd"
              "7f53f42455fff3f9b22f960d12a2587efd6ed0fa3e00dd4645face1b2f1268e6"
              "019be70999eab00f0aeff3cb0e77b7c4a1ab1fdf15d00c4eedd7b75e8cf5c901"
              "19346894089ee0299d58f1d7ebac9b592da2325a5a738ea2baecc1468670f5ae"
              "c880bce32efecfb2a7c5ad3ae4096b0a07aa9bfe6cbaf53da6757377bb692e55"
              "ec8caf5f0af28dafdc42e1d6e5893140945a853f56652c575b99d64399aad2d0"
              "42948575134c8fe638fb0b80ac3a0f08a60f3aa817fe0a24c1fffee6933bd72e"
              "a460e0b241d3f5d98b2321ee25d8c0302353fcfd41bce964d73ff67042286450"
              "6cc56f3470362c90144586ccbfc8e5e6fefbb70429b0a517e4b1badb449cd110"
              "92790aba6e19b914899872f4fb481c8dc47a33422fc05072ac99c958e40dae53"
              "d96ebd87cfbde67a0f050203a89e487da5e03364951830e43771d36abfbe8f5a"
              "7da8e7aa891f36a68dbe9a3b0e3dfbd1afd6327a3ced4a5cd8a5b256fef46d20"
              "0df4af2e2da4dbb786ea0404bb968b6d961e4fc76f89e70ad7c9e11d6aee6526"
              "b75b399811f73c053a29582ba9295ea4d5a8fffb5a8ccbac008d291dd60e2041"
              "371acfc4c432a0ae0fcd8fa25c9551123c95da64caa134edaee5893e19c3c760"
              "75bef419c09681a67f4ede6f28d747b53afd61ddc937d7de96a22c7db10ad870"
              "0cade888de5d6f450c15d796978ddb5e6a52e5044e90247c988686d992105c85"
              "f6d198e2de859330f973ded4d7e5d90de57051dbaf0db0febd4cf9d44da155e5"
              "5293b0930f89c1d21cc227eba9615ca47cce41d16eaddb5bf5dc9bc8477df5cf"
              "21f460b83241e7d0fa3707f9d2b322b9aaa42747d0653168b095ca0a83f38426"
              "688f6f10143cbd1b84c08583b09ed6192c7366ecc23af528fc2e8c585560f9bd"
              "0fcc255b82fc70723a92506bb475ebc1f5ae34a902bf2aa75997ed90a54762c8"
              "e83720833b2fd607eee1beb347a75d3bd0f174ed450a72cce79f1be426de9d6f"
              "1a6feff052674af141b3cea89f8e749118392e9533c62ddad870e60d509fd7ab"
              "fa0bc33c2774b29a0170089b30d82047d6e130c49f6965f9871d1928b7f13e3e"
              "40ad8e3dc85195f4b312f9f6d8e4158aca23a611f6c6c798983555139942536f"
              "6ac59bbd6cc88b9933f22e81429e835bfd4fec27c67520d64a0ad8fd7feb6a3f"
              "be52dc56cbbf59644b0fad0c462ed02ffbf7258e4b94bdedefb187fbdb729a0d"
              "56a36e876ac76de766eed416f39ab4e8b1982b8d0a87cd33182ae81ecf1d1d52"
              "02cc3e82c5762646d15db5f13cde3e81c83715195f9af9f27e01e1829ce529fa"
              "0f715db1f5d227bb201c7c127ea8d0e9c21739c7e9c6a0d8d5a1aaea5216c549"
              "f3715f889e583555ac1bfd77339f3eff1bee75ee2fc45457f5c3ffe9401b8b67"
              "f5bb3f305f3269fe6153ba34de3fa90016c76811cd54b4b49b17b244b1a4f6ed"
              "fa2eaf46e2819aded26005b4ed712e8b700ae7b6123fa2c179640ee523f86436"
              "0d116ee243f13c66d2cd61d422709648d905ab17edf0d0075d2fed443889e153"
              "44069b69b2d3d8273f197f8468baf167074bf6dfdeea5871f0c0652ab2801f39"
              "4ef6fbf841e8072c8bf65026d85d441ca61e78785a2e7ca1e743640fecd6dfad"
              "8b77adcbb8bcb8ce8532ad0cd8b3e51269c26ad037545273f756c1a551192540"
              "8a5045af469ca947f9a3f5457bcc325d05291a192abe75b4da7c97a61adc2fa2"
              "47984edb5a03285f1c3b99f13f6a22f007029faffdd38b62f7bf909ce602e4e0"
              "6ab1ec4543013d354d0dd86d8933a53c17ead02faf0cc740d7191fe475be2f79"
              "40c234f8c73420774a7213fd2a477847527172c02a54928de5fde5f15616760e"
              "6f7ff3c03a233aec880a939d9f1ca68be7f474fd13184fe8f6deb0c4ea01617e"
              "a207d5d765d067fddba58b94f3b59d5996e9f5434f483e2f0079c48050f3ba94"
              "1b589294c41a0f350451d566fe58a9c9688cc3a75da314ff4b3473eeac58664c"
              "5922ae4efae850fe0f7f11dcc089bc0b4df9a64547a35b2559f4a4a3e7d3782d"
              "850997baa589534921becde8dc3f76380ae36bd9730956aae9f59b121d8ae4db"
              "bc586c6b45ad9d5c17cf6821b746177bc9fcb727db3f4aa190688c48826421de"
              "5ebcd429e0d9b479e66e676e8f9a3b4bd92621f47357a7b1b27942121f5a6e00"
              "87e4192a5f8cf4da942cc9d86eac5e"),
          /*context_info=*/
          "some context info",
          /*plaintext=*/
          "08b8b2b733424243760fe426a4b54908"
          "632110a66c2f6591eabd3345e3e4eb98"
          "fa6e264bf09efe12ee50f8f54e9f77b1"
          "e355f6c50544e23fb1433ddf73be84d8"
          "79de7c0046dc4996d9e773f4bc9efe57"
          "38829adb26c81b37c93a1b270b20329d"
          "658675fc6ea534e0810a4432826bf58c"
          "941efb65d57a338bbd2e26640f89ffbc"
          "1a858efcb8550ee3a5e1998bd177e93a"
          "7363c344fe6b199ee5d02e82d522c4fe"
          "ba15452f80288a821a579116ec6dad2b"
          "3b310da903401aa62100ab5d1a36553e"
          "06203b33890cc9b832f79ef80560ccb9"
          "a39ce767967ed628c6ad573cb116dbef"
          "efd75499da96bd68a8a97b928a8bbc10"
          "3b6621fcde2beca1231d206be6cd9ec7"
          "aff6f6c94fcd7204ed3455c68c83f4a4"
          "1da4af2b74ef5c53f1d8ac70bdcb7ed1"
          "85ce81bd84359d44254d95629e9855a9"
          "4a7c1958d1f8ada5d0532ed8a5aa3fb2"
          "d17ba70eb6248e594e1a2297acbbb39d"
          "502f1a8c6eb6f1ce22b3de1a1f40cc24"
          "554119a831a9aad6079cad88425de6bd"
          "e1a9187ebb6092cf67bf2b13fd65f270"
          "88d78b7e883c8759d2c4f5c65adb7553"
          "878ad575f9fad878e80a0c9ba63bcbcc"
          "2732e69485bbc9c90bfbd62481d9089b"
          "eccf80cfe2df16a2cf65bd92dd597b07"
          "07e0917af48bbb75fed413d238f5555a"
          "7a569d80c3414a8d0859dc65a46128ba"
          "b27af87a71314f318c782b23ebfe808b"
          "82b0ce26401d2e22f04d83d1255dc51a"
          "ddd3b75a2b1ae0784504df543af8969b"
          "e3ea7082ff7fc9888c144da2af58429e"
          "c96031dbcad3dad9af0dcbaaaf268cb8"
          "fcffead94f3c7ca495e056a9b47acdb7"
          "51fb73e666c6c655ade8297297d07ad1"
          "ba5e43f1bca32301651339e22904cc8c"
          "42f58c30c04aafdb038dda0847dd988d"
          "cda6f3bfd15c4b4c4525004aa06eeff8"
          "ca61783aacec57fb3d1f92b0fe2fd1a8"
          "5f6724517b65e614ad6808d6f6ee34df"
          "f7310fdc82aebfd904b01e1dc54b2927"
          "094b2db68d6f903b68401adebf5a7e08"
          "d78ff4ef5d63653a65040cf9bfd4aca7"
          "984a74d37145986780fc0b16ac451649"
          "de6188a7dbdf191f64b5fc5e2ab47b57"
          "f7f7276cd419c17a3ca8e1b939ae49e4"
          "88acba6b965610b5480109c8b17b80e1"
          "b7b750dfc7598d5d5011fd2dcc5600a3"
          "2ef5b52a1ecc820e308aa342721aac09"
          "43bf6686b64b2579376504ccc493d97e"
          "6aed3fb0f9cd71a43dd497f01f17c0e2"
          "cb3797aa2a2f256656168e6c496afc5f"
          "b93246f6b1116398a346f1a641f3b041"
          "e989f7914f90cc2c7fff357876e506b5"
          "0d334ba77c225bc307ba537152f3f161"
          "0e4eafe595f6d9d90d11faa933a15ef1"
          "369546868a7f3a45a96768d40fd9d034"
          "12c091c6315cf4fde7cb68606937380d"
          "b2eaaa707b4c4185c32eddcdd306705e"
          "4dc1ffc872eeee475a64dfac86aba41c"
          "0618983f8741c5ef68d3a101e8a3b8ca"
          "c60c905c15fc910840b94c00a0b9d0",
      }};

  for (const TestVector& test_vector : hybrid_decryption_test_vectors) {
    std::unique_ptr<HybridDecrypt> hybrid_decrypt =
        EciesAeadHkdfHybridDecrypt::New(test_vector.private_key).ValueOrDie();
    EXPECT_THAT(hybrid_decrypt->Decrypt(test_vector.ciphertext,
                                        test_vector.context_info),
                IsOkAndHolds(Eq(test_vector.plaintext)));
  }
}

}  // namespace
}  // namespace tink
}  // namespace crypto
