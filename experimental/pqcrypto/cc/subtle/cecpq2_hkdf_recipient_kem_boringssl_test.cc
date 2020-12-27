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

#include "pqcrypto/cc/subtle/cecpq2_hkdf_recipient_kem_boringssl.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "tink/subtle/random.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

class DISABLED_Cecpq2HkdfRecipientKemBoringSslTest : public ::testing::Test {};

// These are the values used by the sender. A recipient using this information
// should successfully produce the shared key listed below.
static const char k_salt_hex[] = "0b0b0b0b";
static const char k_info_hex[] = "0b0b0b0b0b0b0b0b";
static const char k_cecpq2_public_value_correct[] =
    "59fd4b896a3b54a35f98482ab66658e50e8ac2a2b916d564dd3319e85a8fa36b64a7bb3bdb"
    "605cef717d23de87db581a3984ed135422dd3a195d01379496faf2956707d8eca934708c64"
    "313ccf3b8df11f82ecc681de424b986bfe94eda234e91c610561df1772eef40ce19f49ced8"
    "b07e895339703b1245083c7ea0d2c94b35af29a55cbef181816bad443a8a020afa336e1b61"
    "96593da36bd88ce4b3720eade35a7d93dcf9e51ef9c41fb10d5484a74e294c86f628c6530c"
    "c81858196dc01b7012c5ac36ed436c113d910b551892b0807026353838be3ba79b4d3a5186"
    "6fee25b0b7153f9e318ab7b527877da045264e1648027c8e1714fabea49d7cf88ad70a9c61"
    "e74fa52be2b6f9137fe3ece1e6cea24b91b132ea14c0433bbca28f4a46bd7900c7706cee5c"
    "080f049b7b65c57755c0806424566611c0943c262e809055871622d96e2b5c5369b0aa4f7a"
    "89fdff3b6b656fed7080a5c8ad5ecb7a83fe7b62ac3993d72fa4bf370e846cffba61f121e3"
    "7c4c5ea6d8ae97ddc57ca18900b7c213a5ab373b86bdf63eb80524694681b069fd2aeaa07e"
    "db85e8160cc03a45f454a42ae9930cf4581747e3d004be46508d76f6b0f43205070294ecfa"
    "39d371c99c779fe377137fb957be273e8c7ee87e9722b4cc69dc5440195fa72f9212176866"
    "37242753fed48b10e8f764d70e1899c4aacdcadfc83fbc7fe714c8c3d939382f386233b843"
    "df4e4feaeff150b4ad5f5131cc223a87979b47bded793ec7a9756e91374a2e50dbf530375c"
    "3665871c07da7025d83569384f43077d251e989bfd01ab6857c508ddab8f3c54be4257ee90"
    "3c013f231a770b602a8409f3752433d9b215ec8299c71b086bb0d06f9e670e0e41e237e49f"
    "1ef5d2ab12012ad6299d5ffccbfe0e248356b908c253fc1653e770a513981305bbc8f61126"
    "a87836d692a1d826a6573fa6a7f10547588158c207d4a47894b44f5c27dd784f2c17c197d6"
    "a43286a32eefb0068d189b644d90cfbedd505bc617921b5fbe45a205857e3f34a37113129e"
    "767717d9cc5e89fb3b74871c048a200e077a16e945319a05900841a3ffb79943a50b3c0b73"
    "55b96d1cc427c64ac2164e3ac9a21d45ef76a7889d073279e7038a2dad61326c0db37aeee1"
    "502b01b9c54212345a8e377a6aa44fc3a375f2a7f4cfdbfc8e5af689838e953df95c15e99c"
    "b4ee5b6a3ca299e74cd1f6c1e57ea9bd2e2c8a44b00af5bda7009fdf28b679f075a2574c1f"
    "47f182c6ab1b98ef1a736dffa2ca7875f16f9b7b8a900469849036935e2a59e9c30b229beb"
    "0fa888b7fa5a6d36d57a9102580f5463fffffca344df52fb59c103b0368a3d0cde2babe658"
    "5299462397c6f14b8d31d04d09683b9b8df422289329f093dc244028092ae0ed6386c1cf96"
    "6f1959c8cc0466e82b56a90240f5f0d858bf0723e50c09990f3ef19160b108285581250402"
    "8d29f8275032aa6b02efda29456a2c6ea0d0a96d07468052150938c87298139b71d710e16e"
    "914e0a2e65cf1a8280d10302bc681b3b22f8f71d47b7081b39fe7c74b13bc56543cefa4da2"
    "36972fe52d8f0e4e6b66597b5990bcff271892e97d3f6560366943237513c9c8c52d4b5b52"
    "9d3b882aea6d085aa7e293b81380a8d56a6ef809d50d0a";
static const char k_cecpq2_public_value_wrong[] =
    "09fd4b896a3b54a35f98482ab66658e50e8ac2a2b916d564dd3319e85a8fa36b64a7bb3bdb"
    "605cef717d23de87db581a3984ed135422dd3a195d01379496faf2956707d8eca934708c64"
    "313ccf3b8df11f82ecc681de424b986bfe94eda234e91c610561df1772eef40ce19f49ced8"
    "b07e895339703b1245083c7ea0d2c94b35af29a55cbef181816bad443a8a020afa336e1b61"
    "96593da36bd88ce4b3720eade35a7d93dcf9e51ef9c41fb10d5484a74e294c86f628c6530c"
    "c81858196dc01b7012c5ac36ed436c113d910b551892b0807026353838be3ba79b4d3a5186"
    "6fee25b0b7153f9e318ab7b527877da045264e1648027c8e1714fabea49d7cf88ad70a9c61"
    "e74fa52be2b6f9137fe3ece1e6cea24b91b132ea14c0433bbca28f4a46bd7900c7706cee5c"
    "080f049b7b65c57755c0806424566611c0943c262e809055871622d96e2b5c5369b0aa4f7a"
    "89fdff3b6b656fed7080a5c8ad5ecb7a83fe7b62ac3993d72fa4bf370e846cffba61f121e3"
    "7c4c5ea6d8ae97ddc57ca18900b7c213a5ab373b86bdf63eb80524694681b069fd2aeaa07e"
    "db85e8160cc03a45f454a42ae9930cf4581747e3d004be46508d76f6b0f43205070294ecfa"
    "39d371c99c779fe377137fb957be273e8c7ee87e9722b4cc69dc5440195fa72f9212176866"
    "37242753fed48b10e8f764d70e1899c4aacdcadfc83fbc7fe714c8c3d939382f386233b843"
    "df4e4feaeff150b4ad5f5131cc223a87979b47bded793ec7a9756e91374a2e50dbf530375c"
    "3665871c07da7025d83569384f43077d251e989bfd01ab6857c508ddab8f3c54be4257ee90"
    "3c013f231a770b602a8409f3752433d9b215ec8299c71b086bb0d06f9e670e0e41e237e49f"
    "1ef5d2ab12012ad6299d5ffccbfe0e248356b908c253fc1653e770a513981305bbc8f61126"
    "a87836d692a1d826a6573fa6a7f10547588158c207d4a47894b44f5c27dd784f2c17c197d6"
    "a43286a32eefb0068d189b644d90cfbedd505bc617921b5fbe45a205857e3f34a37113129e"
    "767717d9cc5e89fb3b74871c048a200e077a16e945319a05900841a3ffb79943a50b3c0b73"
    "55b96d1cc427c64ac2164e3ac9a21d45ef76a7889d073279e7038a2dad61326c0db37aeee1"
    "502b01b9c54212345a8e377a6aa44fc3a375f2a7f4cfdbfc8e5af689838e953df95c15e99c"
    "b4ee5b6a3ca299e74cd1f6c1e57ea9bd2e2c8a44b00af5bda7009fdf28b679f075a2574c1f"
    "47f182c6ab1b98ef1a736dffa2ca7875f16f9b7b8a900469849036935e2a59e9c30b229beb"
    "0fa888b7fa5a6d36d57a9102580f5463fffffca344df52fb59c103b0368a3d0cde2babe658"
    "5299462397c6f14b8d31d04d09683b9b8df422289329f093dc244028092ae0ed6386c1cf96"
    "6f1959c8cc0466e82b56a90240f5f0d858bf0723e50c09990f3ef19160b108285581250402"
    "8d29f8275032aa6b02efda29456a2c6ea0d0a96d07468052150938c87298139b71d710e16e"
    "914e0a2e65cf1a8280d10302bc681b3b22f8f71d47b7081b39fe7c74b13bc56543cefa4da2"
    "36972fe52d8f0e4e6b66597b5990bcff271892e97d3f6560366943237513c9c8c52d4b5b52"
    "9d3b882aea6d085aa7e293b81380a8d56a6ef809d50d0a";
static const char k_cecpq2_x25519_private_key_hex[] =
    "678b9848a253e45a683a2c23dc798011502962eca5b5756b77efbb7c8339bb83";
static const char k_cecpq2_hrss_private_key_hex[] =
    "000000000000000000000000000000571573a49b032256c90223405140003e6f478d0495ad"
    "cc498324096ad8d14e4288ad090850606c00161109841a10a3820180d1b900800769228024"
    "46ae054980089441401e20c1030b432d8d24044c48e8891dc020341400775df7adbbf76ef7"
    "c9b2a3c07179147f6f7fcde79dafdfc9cbef99effbf34f5fbdedab2f556f7c827e11b9cf9b"
    "70e38203f4dbbffe8b777daed9a57fae577dd16b965ffc9f39d7038f7feffd267c4eccfde9"
    "dffb677cf50972240b488066240488f4528820c8408091e40c929188011217289260005442"
    "929a4204c024002d111220703907b6e050840cc0c414e8e080db2970341027522430e2c887"
    "290dd4011002820880400061820b84cb7a481e0e73f71f4bcb7faf7f9efcdbc937fe4ebcb1"
    "f6df92b7f9e91217f8b3f109575fdadeeb96c174617f15f678f3b9ffb7e873a4acfdcf3cea"
    "e4edff397135f62f5ef73defec9fff3dfc0d1223d369a66ab27fb60b94fffec95f0f7d12ca"
    "0ad309f50caa134d13b3074d0d0d02e3087b18160e5c192908ab0949131f016805e7080202"
    "f600470c9714ca1b690e330cbe14bd002206910645174f05250de210c314441bd915d31d4b"
    "1491025306391c391fe20d4518f60ec417791f6d1a330bb2115110521d0e048e0b201d0a16"
    "d701a30ee506a007fe1df51c3f0ad302d1194f110708f216fb0a6d08740ca20dfa0d00039b"
    "08d71e2a0e0a0f7f1719036d1d690a66142817aa100a17180de003a41b630184171e1a3e0f"
    "171b961df415bd00e511f81e8514250fa30cea06f31809076b12ff10d702a31ef41f351556"
    "180710fa1fe6184903ae13aa16de0981173605bf0b2f108c0f9f176c043905f51d5e17960e"
    "8300f8194502130a7a05310cb519cf05cd1ef116fb0b141e090d49043e12490a531e7316df"
    "01e6086d1e601d34049800fd05b90cee1b61114e05f81d9319a5196305860eda18a209b211"
    "0817cf0424187913a81f8101391faa0bfe001300f70d18079e0c4f010d094a14ee0e751bab"
    "12631db00d1007281cb517031afd182111e408ef0de9166a179006760be4030d17a0192a15"
    "1b03800f9a173c127f014e1da702961eb80ad408111a2810291ffc04b908de1ab611251252"
    "1fc309ce089e0cd2181907960b4d1d09132013a4099e0cc3035e02200c7e1f251ef209130e"
    "9a1bfb01f81b3604710f061333184e060e1cb410f6095f0408007b0c8e00dd05d2031309a3"
    "17a607ab11f5046e0f54088d1cb100b7152718fa120002ad0e4903a30de7115a072e115c13"
    "0316931c161cf600770a8101c003e3176b030f1c0e0ea70f7e00f01f5a133b1a990d140dc8"
    "049f029911960f93067707881b371a3c035803a010b619dd1d2e08e0173b128a0ce405e417"
    "5a011111e1059c1dd61ae104050c0c1dff045c14ee0d670cb619f71db8068b07351a2d004c"
    "0d2f071b17f715b2193d0a0818720336077b0ba50a7b00d010d514330749020f059c197a13"
    "0014130ed603181c98099b0b4d15f919a81e2b124a17eb07d9131a1b4c191e131d0c0f17b0"
    "0eac0cf11a6510390d24167204501baa1c0004a811e3093e0bf7111d1f910b180e60131211"
    "ba06e21d09022e04b61665005b1e2517821310014f0407039c14ef08e20c8f0fa215511483"
    "13c417e51a9814170c3d022601de0c8702fa028a1ffc1b7302bf057612be10a10026093107"
    "4b085d001b0fa30efa0cbf0c2e10690d4c07121fc11ec706731219130002c30471178f1845"
    "0b3a115e1d7d00491eb719a714b30f151a260bcd0e850d2607b8128101a41229117905e40d"
    "ce08b30abf1a2c0e9c16e60c6808be03ae1d4d061a145d15671eaf10ee15701fc4168817f6"
    "10da0f1b0c6604ae0af50f190f0313801e3f1d6a0fa7093718e718a10ed706781fac1e3a1f"
    "42153214d700d50352174319990c5a09d210fe133817b9186a098201661cbd172d131c0585"
    "1a11158414741e65186e12cf1671059d01b513651c5103460b0c0772099619c2137e194e14"
    "5818e30d680d7b131b134e1bad10a0185900f20cec12a010fd1613033402590cb5008f0cbe"
    "0f9505c00a481a6b12c50bf60d790bac05f4019f113104630c531c9916200435124e068e11"
    "c7077a0b0e0c511202199118180401045e0c7b1cc2074516010ffc0dfa0e67024b140b0440"
    "1af914960fc6056d008d0b550e931acd1a3314251af20e69187c0f7903e20be31b5f1a3f1c"
    "c510800fa601ae1352073e07e7185c06eb07140e8f14da0d3b010d108118a81891045e1e12"
    "10300476076d07d508aa080817f61f25199f19c6026915e5131404681b021f1e0461185111"
    "921e0816a613c203ce1b95011605bb1faf187b11ee0ba91d61095908d417cd1a55179700ca"
    "09541a490f2d13411f7e12b811c716241c440cd9085c112f07c816ce05fe0a2e18a300ff10"
    "91067f1c4900e81d9d020118b119dc1cd40a711fcf05b200b7068c109a1a000000000000a0"
    "6b830f8a08eea91fe4276032ef665fdf7a9168fb3e4df90b76c4145fdb911e00";
static const char k_symmetric_key[] =
    "1f482a475391752ea309faa20bbc45e4f0111ffc2cf939cc7295f80c22987223";

// This test evaluates the creation of a Cecpq2HkdfRecipientKemBoringSslTest
// instance with an unknown curve type. It should fail with an util::error::
// UNIMPLEMENTED error.
TEST_F(DISABLED_Cecpq2HkdfRecipientKemBoringSslTest, TestUnknownCurve) {
  // Using all correct values (thus, this test should SUCCEED)
  std::string pub_encoded_hex = k_cecpq2_public_value_correct;
  std::string x25519_priv_hex = k_cecpq2_x25519_private_key_hex;
  std::string hrss_priv_hex = k_cecpq2_hrss_private_key_hex;
  std::string salt_hex = k_salt_hex;
  std::string info_hex = k_info_hex;
  std::string out_key_hex = k_symmetric_key;
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  // Creating the HRSS private key from the hex hard-coded buffer
  util::SecretUniquePtr<struct HRSS_private_key> private_key_hrss =
      util::MakeSecretUniquePtr<struct HRSS_private_key>();
  std::string hrss_privkey_str = test::HexDecodeOrDie(hrss_priv_hex);
  std::copy(hrss_privkey_str.data(),
            &(hrss_privkey_str.data()[sizeof(private_key_hrss->opaque)]),
            private_key_hrss->opaque);

  // Creating the CECPQ2 recipient KEM using HRSS and X25519 private keys
  auto status_or_recipient_kem = Cecpq2HkdfRecipientKemBoringSsl::New(
      EllipticCurveType::UNKNOWN_CURVE,
      util::SecretDataFromStringView(test::HexDecodeOrDie(x25519_priv_hex)),
      std::move(private_key_hrss));

  // The instance creation above should fail with an unimplemented algorithm
  // error given the UNKNOWN_CURVE parameter
  EXPECT_EQ(util::error::UNIMPLEMENTED,
            status_or_recipient_kem.status().error_code());
}

// This test evaluates the case where a unsupported curve (NIST_P256) is
// specified. This test should fail with an util::error::UNIMPLEMENTED error.
TEST_F(DISABLED_Cecpq2HkdfRecipientKemBoringSslTest, TestUnsupportedCurve) {
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }
  // Using all correct values (thus, this test should SUCCEED)
  std::string pub_encoded_hex = k_cecpq2_public_value_correct;
  std::string x25519_priv_hex = k_cecpq2_x25519_private_key_hex;
  std::string hrss_priv_hex = k_cecpq2_hrss_private_key_hex;
  std::string salt_hex = k_salt_hex;
  std::string info_hex = k_info_hex;
  std::string out_key_hex = k_symmetric_key;

  // Creating the HRSS private key from the hex hard-coded buffer
  util::SecretUniquePtr<struct HRSS_private_key> private_key_hrss =
      util::MakeSecretUniquePtr<struct HRSS_private_key>();
  std::string hrss_privkey_str = test::HexDecodeOrDie(hrss_priv_hex);
  std::copy(hrss_privkey_str.data(),
            &(hrss_privkey_str.data()[sizeof(private_key_hrss->opaque)]),
            private_key_hrss->opaque);

  // Creating the CECPQ2 recipient KEM using HRSS and X25519 private keys
  auto status_or_recipient_kem = Cecpq2HkdfRecipientKemBoringSsl::New(
      EllipticCurveType::NIST_P256,
      util::SecretDataFromStringView(test::HexDecodeOrDie(x25519_priv_hex)),
      std::move(private_key_hrss));

  // The instance creation above should fail with an unimplemented algorithm
  // error given the UNKNOWN_CURVE parameter
  EXPECT_EQ(util::error::UNIMPLEMENTED,
            status_or_recipient_kem.status().error_code());
}

TEST_F(DISABLED_Cecpq2HkdfRecipientKemBoringSslTest, TestRecipientFlowSuccess) {
  EllipticCurveType curve = EllipticCurveType::CURVE25519;
  HashType hash_type = HashType::SHA256;
  EcPointFormat point_format = EcPointFormat::COMPRESSED;

  // Using all correct values (thus, this test should SUCCEED)
  std::string pub_encoded_hex = k_cecpq2_public_value_correct;
  std::string x25519_priv_hex = k_cecpq2_x25519_private_key_hex;
  std::string hrss_priv_hex = k_cecpq2_hrss_private_key_hex;
  std::string salt_hex = k_salt_hex;
  std::string info_hex = k_info_hex;
  int out_len = 32;
  std::string out_key_hex = k_symmetric_key;
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  // Creating the HRSS private key from the hex hard-coded buffer
  util::SecretUniquePtr<struct HRSS_private_key> private_key_hrss =
      util::MakeSecretUniquePtr<struct HRSS_private_key>();
  std::string hrss_privkey_str = test::HexDecodeOrDie(hrss_priv_hex);
  std::copy(hrss_privkey_str.data(),
            &(hrss_privkey_str.data()[sizeof(private_key_hrss->opaque)]),
            private_key_hrss->opaque);

  // Creating the CECPQ2 recipient KEM using HRSS and X25519 private keys
  auto cecpq2_kem_or = Cecpq2HkdfRecipientKemBoringSsl::New(
      curve,
      util::SecretDataFromStringView(test::HexDecodeOrDie(x25519_priv_hex)),
      std::move(private_key_hrss));
  ASSERT_TRUE(cecpq2_kem_or.ok());
  auto cecpq2_kem = std::move(cecpq2_kem_or).ValueOrDie();

  // Recovering the symmetric key
  auto kem_key_or = cecpq2_kem->GenerateKey(
      test::HexDecodeOrDie(pub_encoded_hex), hash_type,
      test::HexDecodeOrDie(salt_hex), test::HexDecodeOrDie(info_hex), out_len,
      point_format);
  ASSERT_TRUE(kem_key_or.ok());

  // In this test, the symmetric keys should match
  EXPECT_EQ(
      out_key_hex,
      test::HexEncode(util::SecretDataAsStringView(kem_key_or.ValueOrDie())));
}

TEST_F(DISABLED_Cecpq2HkdfRecipientKemBoringSslTest, TestRecipientFlowFailure) {
  EllipticCurveType curve = EllipticCurveType::CURVE25519;
  HashType hash_type = HashType::SHA256;
  EcPointFormat point_format = EcPointFormat::COMPRESSED;

  // Using a modified public value (thus, this test should FAIL)
  std::string pub_encoded_hex = k_cecpq2_public_value_wrong;
  std::string x25519_priv_hex = k_cecpq2_x25519_private_key_hex;
  std::string hrss_priv_hex = k_cecpq2_hrss_private_key_hex;
  std::string salt_hex = k_salt_hex;
  std::string info_hex = k_info_hex;
  int out_len = 32;
  std::string out_key_hex = k_symmetric_key;
  if (kUseOnlyFips) {
    GTEST_SKIP() << "Not supported in FIPS-only mode";
  }

  // Creating the HRSS private key from the hex hard-coded buffer
  util::SecretUniquePtr<struct HRSS_private_key> private_key_hrss =
      util::MakeSecretUniquePtr<struct HRSS_private_key>();
  std::string hrss_privkey_str = test::HexDecodeOrDie(hrss_priv_hex);
  std::copy(hrss_privkey_str.data(),
            &(hrss_privkey_str.data()[sizeof(private_key_hrss->opaque)]),
            private_key_hrss->opaque);

  // Creating the CECPQ2 recipient KEM using HRSS and X25519 private keys
  auto cecpq2_kem_or = Cecpq2HkdfRecipientKemBoringSsl::New(
      curve,
      util::SecretDataFromStringView(test::HexDecodeOrDie(x25519_priv_hex)),
      std::move(private_key_hrss));
  ASSERT_TRUE(cecpq2_kem_or.ok());
  auto cecpq2_kem = std::move(cecpq2_kem_or).ValueOrDie();

  // Recovering the symmetric key
  auto kem_key_or = cecpq2_kem->GenerateKey(
      test::HexDecodeOrDie(pub_encoded_hex), hash_type,
      test::HexDecodeOrDie(salt_hex), test::HexDecodeOrDie(info_hex), out_len,
      point_format);
  ASSERT_TRUE(kem_key_or.ok());

  // In this test, the shared secrets should NOT match because the public value
  // has been modified
  EXPECT_NE(
      out_key_hex,
      test::HexEncode(util::SecretDataAsStringView(kem_key_or.ValueOrDie())));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
