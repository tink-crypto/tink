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

class Cecpq2HkdfRecipientKemBoringSslTest : public ::testing::Test {};

// These are the values used by the sender. A recipient using this information
// should successfully produce the shared key listed below.
static const char k_salt_hex[] = "0b0b0b0b";
static const char k_info_hex[] = "0b0b0b0b0b0b0b0b";
static const char k_cecpq2_public_value_correct[] =
    "37cfa8b7614b7b5822c5cbf6bdf960a53a941136b2bca1ab09717e999df0766e4817d2b1ef"
    "eebd63b63fb6ce49886233d8ac45c0c62b5e066a2f2737c07d4b6955c71cc6e1912151ae3c"
    "7e821c23bf56edb98ca1d94eb44de5a70c824aee200070e9b619290db6a2217a24035156b9"
    "88b0b26140a843737d77567515b8a6c2d1d637aa9a87a761a2b3219d17517c661bdc9c390d"
    "04c62887dae750962935dfdacdf979486582abfeaa8defecf06b5013e323ed2802ef2bf607"
    "428c3c326ea7f789daa5753fd95cbbf59606dbf549c58f4bf7351931f921424f7d1ca4f9ca"
    "da3e67a335f03a4bbfe5d309303f20102f8fab825a535585b6fdec82764fbb9f91e2f9d4f3"
    "3ef701b5cb7370ee98642945d1f722e959f6093ffaafeee48e2689e35618da0b5ab7c79f1f"
    "5db3af54c7b3d103f88856e5ec467d979d4e112f0aeeb1777abbe825224ad69f34264810d7"
    "5993fbe0c69a7cf90cc33e75b638213b66f9150eee0c9f343d9748aaa139f4718c38b705d6"
    "c908e6aad4b98adb557e900187feeab40cc851420ec0cb967d7919d560ecb3a169671dc5d0"
    "186897257a2eea2fc907a362114c84f10203f7f5242fff0f65694bf713782d16543dbaa939"
    "7d63755dad01efce75b8b6278e47be6831073e47a61fdecdcb8171166adfc0bbda6fdd75ce"
    "0b5b69b3fc70b96031f727b41f4335a077e9927f2d5dd8ae22ecd074f19d529ff7bdee3c33"
    "1369e53112f34dfefdfcbdd65db01ac7bae50d7874991ef3c55a25f87f6b36b1b9367fcee7"
    "592f5a48c9d32789d4541c9f5bf10a875e1d2517e36cb7e94bf964df5e976c97712a31cf1b"
    "f291baeec42a057a1b49686692fd99ab9f9c4e72b6421da7dc414f58481a828df1deac589c"
    "c5624935362162a431554c4e0ce420d8651219a24a17461a1595fd4ca055a8bd05120fc149"
    "48bdbab537213cb23213687e8c7ddb67dc7465b3fb97efcdda38178db2fef873c84c156957"
    "6638f11943803eb24ff5aa3e26f954052a0a6d4273e2ecebe452945d107d57a320bf0fe5fa"
    "37aba21764661fdaea352c3e11d8d864a34c92d434c122f6064055e4c22c922d3e6d68afec"
    "b2f2fb49f7a50f3b7f2b3cf776a28d58c055dd13fa37ff11832e59a5d64b6de0e113a8395e"
    "36c697119ebdf501bf633f803f96714b401ea92f0796373e0344c8bab0cf106683e2e9a53a"
    "1eb24be0ccbae524ad8974cb64e5f75b8fd3b852913686dcd2fed06ffe41eb76a5048f89c7"
    "25930de821e0712d1f637d38ac2bdd72b96f59d43b1f0fd8c9e14e5b71ea8da75fa3b53465"
    "6b884632161be06f09932c206d5bcee2e05bc4ccc7e1382d5fb1302914b72516f204402cc5"
    "0e7f7051097193706812a1190a6b6d7413e3ce1a49b0ddf0f356279a68f7460c47dce639f4"
    "96fc1d65b043ab97bcc8af12fe651647d3f284ac600faec938919a790cec60af264bbbb877"
    "26740380458b4b58f34ac1a770de59abfafa129665c1c6941000704b399c499bdd4bf89239"
    "3d9936e17955aad01d645267e8c086bbc3e8230a979a5ba65e48e216e2323d5cbfcc1d97ff"
    "23474591fb2c7424d4c6ff4dd166fe982b6392620040984f2cc03fb4004df3b703b961570b"
    "3171242adb40d73ab5b08c030d27071c65368d6ef1d509";
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
    "cfd3443e58430fe7fb0e70afdbd13bf963ee165ea606f9ac8ea6c63cc5ae8b8b";
static const char k_cecpq2_hrss_private_key_hex[] =
    "000000000000000006371886c982481000c268208a22525f8421160233800202148aa30700"
    "0ca400804c0b223a2a602980b03b2090f1ce59019af84ea114d510a4a04a7ae5411d394c12"
    "910618350d06a902c086c146140020128315500740004f377ff7fbb67d9ab4ef7de49f2f5f"
    "ffad7dd6d3bfb16e2bffcfa7cf4f4cade0feed0b6bbbae777f84b67fec97f9cff9b5fefafe"
    "f33eff7ea6e94e7fefd7bfb95c5ed14e9e378d1ffd7ef9fed7e69507fc3bf33dff5f7d0602"
    "0132415b8a3922e800c0848686a9804540f9a1300920188c09ca701d055a980ac840b18dd8"
    "88318512bb200905a5c4814414d08086080821ac029130b2acf415015019020218475d305f"
    "18b80012055cc302748b0501080b8b72e5df9fb97bef46e787d796b9dbef68fdb53f593b7e"
    "ec6bcff83f455effeff976f78fdfa8358597fbbfc915b5cfdd4c3dfecaa6dc5f29ae4b9bfb"
    "f6effc1dc7dc59d6d25a4ffffa5f3cbd0a1e6f5de3967eafffa90e391ce20e4913cc0a7701"
    "b5138e04c409e509280bbb1099007e104606b11e0b06ea041e17821d5c1ab505c81d650a20"
    "0eae0cfb1e1b1b9b1c1d062912c404880fd1035c0145022a1a3d1cc30bcb0707073008d619"
    "8211cd0f710754026007811be212e61c000fbd196b0c511d2e02111b37045d1b4f0ecf0f57"
    "0f7f1fad0fcd055e09b811a616ce152509f0029103a112691ce11e700405158602520e160a"
    "870ffe065c0b33090e08bc156c00ea0c5f1cb80f690ffe103a136e059810c60d2603490fdb"
    "1256178616cb080d1b58023f13430bf71e9d022a11a500d607e1111b1ddd1f6f123c17d11b"
    "6416cb039b14c2038e12ed10d610750f43164600c508ae0a0f11eb1f6219021f23028e1cc1"
    "1c34113708270c321e911f9e07270b6e16511557092e1f86082009ff0d9914c71aa71e6609"
    "2b02130f0302c0071618550c871001066c16fb111a0bac1b531585159c0aeb108200ae1db2"
    "17f815f2141c093007d208a11132183c13c912880b1107ff0d4e0c6312d310470e8e189d17"
    "68100a0c53146f1cfc07e615931cdb1b581602172001e106a4176019d21ebf095a029802e2"
    "1b1f05ec0f0a0c8d111a0d550453128806b80b6a0f9405ba0dfb1f250e2b1ad3111d026b06"
    "c81f3f080c17b515310cd217da0cd01ff607ea1a5710440417121518330726008a077802c8"
    "1aeb1d1805540bee0ad4191e12f414651844041308050d2314e7002303a91119142c042519"
    "f70e9d060a1dd71d57199400751eeb001707b9175f054c16141b8505611d2703f30dd30d68"
    "0237136a1a5d1e2c079d06e40d2f134c128c0e50176601fd0e61169a178201b11db8070f14"
    "2e14bd0e760b7501961c700f0017b013f71f700f39178b1b771a0d1b6f12a200c308ca0531"
    "062e13b10d9305bf03a116071947186b03bc1005078a1287157102b115d806f704341de703"
    "890ea91eb514b208661a1a1a1a116c08cb19291c7b08f3165216f2099609570ce10712065b"
    "00211a240e3c139f078d110212b005cd16611f7f1bb606dc086e121a16ba0b74165d0d0f0d"
    "0c1fc81f6609fd1ea1021e0f2c0d0a0b31102e039d1a1d06e5093505d51aab09a6043c1cd4"
    "13e71e370f621dd5073915b51836003110760abd1fe115481a8908c71a320ddf1d8c1eb414"
    "6810960c7f071616061a26129d02d2067705a7175206a305240e2a13bb10d2010e07e51362"
    "1fd810eb123214991acc025d113a07100dae10ad04c807f011710d1a137508311477106704"
    "621e0203550a2819fe1c801ac208fd04d41b310e141f550e3300de0954176d1fdd15c20371"
    "1bb40fd30aa00ad807671cc817421b3106d8128f00b408da19260d661cf80d0b1f96079a0c"
    "801a65048313db156f09f61180180b1a2f1af70daf13c009ef098716850ba102131eb1042c"
    "0502197102531e3e17e40d730d96173409851412067f1e3806191c110090012418bb1f7e04"
    "22174e0c7c16cf0bac07e9163313cf01071f6e087403711d6d07880dca0f8d08ab06610f06"
    "0a3b016e13ee15570c6d0271054f05aa01db0b4615fa08d502310e541eff078c1fc314c602"
    "a31d811b9c11251cf70ab11c22194b05320e810bf7075f058f0516081d0c96058b09970ed5"
    "15780e5301e31db11ce61df70a3f04a1034408ff073d00d308880f69119306700f0d153e17"
    "6e0aa205330faf12f519e710cd1e4309091d2207a00bc0081314fc1da114851ef013060f80"
    "0c480c9417a81eac017a0b8b07681aca0fe70196134104b01c621cc90ae5056b17e519261f"
    "97180014b11f811f4809580dfd1ffa1aa81f4506851b350ed300951a9c16820f7b026a13f2"
    "0e8a16f81c110f68192711bc0e6417fe08ae09cf0bb8151f02760e1301e90bc41a051acd03"
    "6310a418771e25063302a80d011f2417031b1e1d5c1adf17d001b106b600fa06fc15e31368"
    "0520065c096b1c881dda06c20f801c9505e801e00dd0040000000000004bece6a3e58b7d19"
    "337ba8a3297d786123ed0248cbb6f954faf0a2b31a0a2ac00000000000000000";
static const char k_symmetric_key[] =
    "93255f97e01b4a2afc77bc228a6c110bf855ad6c9993b982a44dad89cf05ff91";

// This test evaluates the creation of a Cecpq2HkdfRecipientKemBoringSslTest
// instance with an unknown curve type. It should fail with an util::error::
// UNIMPLEMENTED error.
TEST_F(Cecpq2HkdfRecipientKemBoringSslTest, TestUnknownCurve) {
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
TEST_F(Cecpq2HkdfRecipientKemBoringSslTest, TestUnsupportedCurve) {
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

TEST_F(Cecpq2HkdfRecipientKemBoringSslTest, TestRecipientFlowSuccess) {
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

TEST_F(Cecpq2HkdfRecipientKemBoringSslTest, TestRecipientFlowFailure) {
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
