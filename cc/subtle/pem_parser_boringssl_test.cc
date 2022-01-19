// Copyright 2018 Google Inc.
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
#include "tink/subtle/pem_parser_boringssl.h"

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/strings/ascii.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/bio.h"
#include "openssl/bn.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "tink/internal/bn_util.h"
#include "tink/internal/err_util.h"
#include "tink/internal/rsa_util.h"
#include "tink/internal/ssl_unique_ptr.h"
#include "tink/internal/ssl_util.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::test::IsOk;
using ::crypto::tink::test::StatusIs;
using ::testing::Eq;
using ::testing::Not;
using ::testing::NotNull;
using ::testing::Test;
using ::testing::TestWithParam;
using ::testing::ValuesIn;

// Test vectors for ECDSA were generated using the `openssl` command.
//
// 1. Generate private PEM file. In the command below, the following values were
// used for the -name flag: {prime256v1, secp384r1, secp521r1}.
//
// $ openssl ecparam -genkey -name prime256v1 -noout -out ec-key-pair.pem
//
// 2. Generate public PEM file from private PEM file.
//
// $ openssl ec -in ec-key-pair.pem -pubout -out pub.pem
//
// 3. Print public X, Y and private key components. The public component is
// obtained by removing the leading "04" character (which indicates that the key
// is not compressed) and splitting the remaning bytes in two. The first half is
// X and the 2nd half is Y.
//
// $ openssl ec -in ec-key-pair.pem -text -param_enc explicit -noout
struct EcKeyTestVector {
  // EC format
  subtle::EllipticCurveType curve;
  std::string pub_x_hex_str;
  std::string pub_y_hex_str;
  std::string priv_hex_str;

  // PEM format
  std::string pub_pem;
  std::string priv_pem;
};

std::vector<EcKeyTestVector> GetEcKeyTestVectors() {
  return {
      {
          /*.curve=*/subtle::NIST_P256,
          /*.pub_x_hex_str=*/
          "1455cfd594d44df125f1ff643636740c6cc59972091fee6fa9b8d3897d59b0e0",
          /*.pub_y_hex_str=*/
          "d0b655238d8c0cebbfde77b1fda62ad19ccc6bf25a4ebf5637d3597983094363",
          /*.priv_hex_str=*/
          "8485FB768E109D14BE1E219D4D806523308E0E401DB1DE95DC938E8903C49B2C",
          /*.pub_pem=*/R"(-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEFFXP1ZTUTfEl8f9kNjZ0DGzFmXIJ
H+5vqbjTiX1ZsODQtlUjjYwM67/ed7H9pirRnMxr8lpOv1Y301l5gwlDYw==
-----END PUBLIC KEY-----)",
          /*.priv_pem=*/R"(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIISF+3aOEJ0Uvh4hnU2AZSMwjg5AHbHeldyTjokDxJssoAoGCCqGSM49
AwEHoUQDQgAEFFXP1ZTUTfEl8f9kNjZ0DGzFmXIJH+5vqbjTiX1ZsODQtlUjjYwM
67/ed7H9pirRnMxr8lpOv1Y301l5gwlDYw==
-----END EC PRIVATE KEY-----)",
      },
      {
          /*.curve=*/subtle::NIST_P256,
          /*.pub_x_hex_str=*/
          "ee21893b340260360f1ae3d26bf0a066eadc8c63690b2f1de308220800d9d1ab",
          /*.pub_y_hex_str=*/
          "d334a5917d2be49475af2454feea41d4418ea99eec791d1a0cc1c2890f8b33ee",
          /*.priv_hex_str=*/
          "cac853f79a95c7d8697d0469ccda4faf940d80d1e0c81ffa0e6082ed9a85654b",
          /*.pub_pem=*/R"(-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7iGJOzQCYDYPGuPSa/CgZurcjGNp
Cy8d4wgiCADZ0avTNKWRfSvklHWvJFT+6kHUQY6pnux5HRoMwcKJD4sz7g==
-----END PUBLIC KEY-----)",
          /*.priv_pem=*/R"(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIMrIU/ealcfYaX0EaczaT6+UDYDR4Mgf+g5ggu2ahWVLoAoGCCqGSM49
AwEHoUQDQgAE7iGJOzQCYDYPGuPSa/CgZurcjGNpCy8d4wgiCADZ0avTNKWRfSvk
lHWvJFT+6kHUQY6pnux5HRoMwcKJD4sz7g==
-----END EC PRIVATE KEY-----)",
      },
      {
          // example EcKey with a pub_x with a leading zero.
          /*.curve=*/subtle::NIST_P256,
          /*.pub_x_hex_str=*/
          "00b02778da7b7bfd7094c36f847eb32b3077547da49c8ecf667f7acc3145693c",
          /*.pub_y_hex_str=*/
          "710f3044af1cfe55f10d75de077297f7f2745cf2cd6cd4306f2aa72e367f7331",
          /*.priv_hex_str=*/
          "f4b9b38fd2817527e5b6ef7910bce594f06d87990f31a2e9005594951e2a2f2f",
          /*.pub_pem=*/R"(-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEALAneNp7e/1wlMNvhH6zKzB3VH2k
nI7PZn96zDFFaTxxDzBErxz+VfENdd4Hcpf38nRc8s1s1DBvKqcuNn9zMQ==
-----END PUBLIC KEY-----)",
          /*.priv_pem=*/R"(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPS5s4/SgXUn5bbveRC85ZTwbYeZDzGi6QBVlJUeKi8voAoGCCqGSM49
AwEHoUQDQgAEALAneNp7e/1wlMNvhH6zKzB3VH2knI7PZn96zDFFaTxxDzBErxz+
VfENdd4Hcpf38nRc8s1s1DBvKqcuNn9zMQ==
-----END EC PRIVATE KEY-----)",
      },
      {
          // example EcKey with a priv with a leading zero.
          /*.curve=*/subtle::NIST_P256,
          /*.pub_x_hex_str=*/
          "8b348ef165b90ea991c28f254a5caed293e42d6c64fa2db1f3991c007442bf68",
          /*.pub_y_hex_str=*/
          "2d45951a61ac6f99d9c6745fe129e86c74001d3c13f506f9bb2d10fd492069b4",
          /*.priv_hex_str=*/
          "006484950d48016cc524078de3e3216258d2bc563f2318cc49f0301059f5fd61",
          /*.pub_pem=*/R"(-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEizSO8WW5DqmRwo8lSlyu0pPkLWxk
+i2x85kcAHRCv2gtRZUaYaxvmdnGdF/hKehsdAAdPBP1Bvm7LRD9SSBptA==
-----END PUBLIC KEY-----)",
          /*.priv_pem=*/R"(-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIABkhJUNSAFsxSQHjePjIWJY0rxWPyMYzEnwMBBZ9f1hoAoGCCqGSM49
AwEHoUQDQgAEizSO8WW5DqmRwo8lSlyu0pPkLWxk+i2x85kcAHRCv2gtRZUaYaxv
mdnGdF/hKehsdAAdPBP1Bvm7LRD9SSBptA==
-----END EC PRIVATE KEY-----)",
      },
      {
          /*.curve=*/subtle::NIST_P384,
          /*.pub_x_hex_str=*/
          "49b1a78537281c81984e00092f04c22c610cac2aba7a3de992bf6ad22305d2d54501"
          "87"
          "57ed823c643334e18d95b2e642",
          /*.pub_y_hex_str=*/
          "d2a851445c5da0bf0d543eaad5ff98634483c549d96045243121ed6d5c9ba64dab65"
          "6a"
          "6d25e018b01c4d3ab3f1738989",
          /*.priv_hex_str=*/
          "0254cd5840eec13b0d68ba08fdbc147c22906046ecb2fca2625294be74dea29aa370"
          "fd"
          "830985d278099644ecf89167cd",
          /*.pub_pem=*/R"(-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAESbGnhTcoHIGYTgAJLwTCLGEMrCq6ej3p
kr9q0iMF0tVFAYdX7YI8ZDM04Y2VsuZC0qhRRFxdoL8NVD6q1f+YY0SDxUnZYEUk
MSHtbVybpk2rZWptJeAYsBxNOrPxc4mJ
-----END PUBLIC KEY-----)",
          /*.priv_pem=*/R"(-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDACVM1YQO7BOw1ougj9vBR8IpBgRuyy/KJiUpS+dN6imqNw/YMJhdJ4
CZZE7PiRZ82gBwYFK4EEACKhZANiAARJsaeFNygcgZhOAAkvBMIsYQysKrp6PemS
v2rSIwXS1UUBh1ftgjxkMzThjZWy5kLSqFFEXF2gvw1UPqrV/5hjRIPFSdlgRSQx
Ie1tXJumTatlam0l4BiwHE06s/FziYk=
-----END EC PRIVATE KEY-----)",
      },
      {
          /*.curve=*/subtle::NIST_P384,
          /*.pub_x_hex_str=*/
          "82de2530a8d589149c8a60fdd529ed7a465db62d7412771a7ec40a69be139226b609"
          "06"
          "cc784007d8e28a79dca528e66c",
          /*.pub_y_hex_str=*/
          "c41f7532b8325aad3f1dddebddb702ebe70259bb5730e6bc4a75baec0d85c52d0d00"
          "c8"
          "e372d1da0d1ca10136e4cfd262",
          /*.priv_hex_str=*/
          "a6a8415b526418966758cfda45c19b4fe0ac4cf06d301b195ffea231d0eda67a54fb"
          "7c"
          "bc12470296e29e86359de53aee",
          /*.pub_pem=*/R"(-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEgt4lMKjViRScimD91SntekZdti10Enca
fsQKab4Tkia2CQbMeEAH2OKKedylKOZsxB91MrgyWq0/Hd3r3bcC6+cCWbtXMOa8
SnW67A2FxS0NAMjjctHaDRyhATbkz9Ji
-----END PUBLIC KEY-----)",
          /*.priv_pem=*/R"(-----BEGIN EC PRIVATE KEY-----
MIGkAgEBBDCmqEFbUmQYlmdYz9pFwZtP4KxM8G0wGxlf/qIx0O2melT7fLwSRwKW
4p6GNZ3lOu6gBwYFK4EEACKhZANiAASC3iUwqNWJFJyKYP3VKe16Rl22LXQSdxp+
xAppvhOSJrYJBsx4QAfY4op53KUo5mzEH3UyuDJarT8d3evdtwLr5wJZu1cw5rxK
dbrsDYXFLQ0AyONy0doNHKEBNuTP0mI=
-----END EC PRIVATE KEY-----)",
      },
      {
          /*.curve=*/subtle::NIST_P521,
          /*.pub_x_hex_str=*/
          "01d09ee2f33ce601d8594b09e668e128a7708ce752ef589d1a2c405523db0b68a0cb"
          "58"
          "60359b12c5371fc462f4142339ca7ff2550833f0a64887951ddb64e7d139d5",
          /*.pub_y_hex_str=*/
          "01b45ce12804afcf17fbd60728d362d4787b750d561e52144fd517807ddaa2b396be"
          "d9"
          "98227a5696d9c997a1cf0b6f1a3724ce25c7396dc2ea62c4bdf467061916e3",
          /*.priv_hex_str=*/
          "01f1913a921271c06686482a51dbf2c853aefbcc62b2b23d473a4c818d570e555667"
          "42"
          "edd9f05d0532f73d40c11d3d31c3734e4470cc0491ad911a209f1e88dcd712",
          /*.pub_pem=*/R"(-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB0J7i8zzmAdhZSwnmaOEop3CM51Lv
WJ0aLEBVI9sLaKDLWGA1mxLFNx/EYvQUIznKf/JVCDPwpkiHlR3bZOfROdUBtFzh
KASvzxf71gco02LUeHt1DVYeUhRP1ReAfdqis5a+2ZgielaW2cmXoc8Lbxo3JM4l
xzltwupixL30ZwYZFuM=
-----END PUBLIC KEY-----)",
          /*.priv_pem=*/R"(-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIB8ZE6khJxwGaGSCpR2/LIU677zGKysj1HOkyBjVcOVVZnQu3Z8F0F
Mvc9QMEdPTHDc05EcMwEka2RGiCfHojc1xKgBwYFK4EEACOhgYkDgYYABAHQnuLz
POYB2FlLCeZo4SincIznUu9YnRosQFUj2wtooMtYYDWbEsU3H8Ri9BQjOcp/8lUI
M/CmSIeVHdtk59E51QG0XOEoBK/PF/vWByjTYtR4e3UNVh5SFE/VF4B92qKzlr7Z
mCJ6VpbZyZehzwtvGjckziXHOW3C6mLEvfRnBhkW4w==
-----END EC PRIVATE KEY-----)",
      },
      {
          /*.curve=*/subtle::NIST_P521,
          /*.pub_x_hex_str=*/
          "0108803f92f8449fdfca02c8c2b49643f407f63dda728ad38e3598b887b5831ab063"
          "d9"
          "60c5fd321ee597f4273fc0596015ce406515a2ab24a7c96a44802d74c3ac7b",
          /*.pub_y_hex_str=*/
          "01f216dc0f590b920d9c026e0aedc2b1cfe85d4f2d607db632395c7f64c053285936"
          "33"
          "635b6ad8bf51d2ee70c88000e96fd340601211c1d1eb0b32773806506b47b0",
          /*.priv_hex_str=*/
          "0010a207e650cf531c98c0c6d1cfdb88a5ee57f02734cbab93b8ae30d9dac0845d17"
          "61"
          "9be33f9aeaeab35401e63a149a87ae45b45bf2fea125d96c5d418d96bcda85",
          /*.pub_pem=*/R"(-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBCIA/kvhEn9/KAsjCtJZD9Af2Pdpy
itOONZi4h7WDGrBj2WDF/TIe5Zf0Jz/AWWAVzkBlFaKrJKfJakSALXTDrHsB8hbc
D1kLkg2cAm4K7cKxz+hdTy1gfbYyOVx/ZMBTKFk2M2Nbati/UdLucMiAAOlv00Bg
EhHB0esLMnc4BlBrR7A=
-----END PUBLIC KEY-----)",
          /*.priv_pem=*/R"(-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIAEKIH5lDPUxyYwMbRz9uIpe5X8Cc0y6uTuK4w2drAhF0XYZvjP5rq
6rNUAeY6FJqHrkW0W/L+oSXZbF1BjZa82oWgBwYFK4EEACOhgYkDgYYABAEIgD+S
+ESf38oCyMK0lkP0B/Y92nKK0441mLiHtYMasGPZYMX9Mh7ll/QnP8BZYBXOQGUV
oqskp8lqRIAtdMOsewHyFtwPWQuSDZwCbgrtwrHP6F1PLWB9tjI5XH9kwFMoWTYz
Y1tq2L9R0u5wyIAA6W/TQGASEcHR6wsydzgGUGtHsA==
-----END EC PRIVATE KEY-----)",
      },
  };
}

// Holds test vectors for the PemParser. The original private-key pem text was
// taken from
// google3/third_party/tink/java_src/src/test/java/com/google/crypto/tink/subtle/PemKeyTypeTest.java.
// The components and public-key PEM version were extracted using
//
// $ openssl rsa -in <pem file> -pubout -text
struct RsaKeyTestVector {
  // RSA parameters.
  absl::string_view modulus_hex_str;
  absl::string_view public_exponent_hex_str;

  absl::string_view private_exponent_hex_str;
  absl::string_view p_hex_str;
  absl::string_view q_hex_str;
  absl::string_view dp_hex_str;
  absl::string_view dq_hex_str;
  absl::string_view coefficient_hex_str;

  // PEM forms.
  absl::string_view public_pem;
  absl::string_view private_pem;
};

std::vector<RsaKeyTestVector> GetRsaKeyTestVectors() {
  return {
      {/*.modulus_hex_str=*/
       "00bc067ea9038c24b063cac6146b26793499cc8a93985208596b9700acd4e51a580413"
       "316cc5acc5b499d4781421ba9b0d8af75ae56b6179d5a7fc2098f2fc4d366a6a4166b1"
       "5f2254db1cb3ce5dd4ab80bd8bd5adb5df34b602c319d4d004299c06e5e2437fd626e2"
       "84c29eeb79d1820b830b706072efa2fd1c8898d1eaaf39fb9f54ce7671ea2b5512a429"
       "0d3ec58bb41639a19be6630b1c27059b9a32505bebc6f42b301f9fb2cf2b624c1b6598"
       "702bbeaed38b5fd9941d661ff6adca65ffb251d1f314bced0861fa30ec676e2129e5ac"
       "ba03a6cb7594f93c60cef9b2aeee45edc6aadd31f841ee1f37fd63ccff3cebbb018a3d"
       "631b3d498a79348704bb419f",
       /*.public_exponent_hex_str=*/"010001",
       /*.private_exponent_hex_str=*/
       "718b1a81c5faa34d4175fa17ea7cd944c27b9a5376f052ca6d064b0a13a6263a707b86"
       "a540da0ca9fb1b2b483cf60b1c2a872504d5cb8f5f4e8a1ac54236ca09ca4950254b87"
       "3f9c2e952e9fb859ed17595f50320e5a33e295d86b88eff5138b7d3ee55c0d9eacecad"
       "6f39b8c95f9340906a1ffa9e6dc7e7418bdb7d28539897297c7da5358867e60dfe8c76"
       "fbf5a6a4c064e0f6af1bf3c9640cbee007aea3be81017b726d088b69957b844f951fac"
       "323ff3e79fd67daf32a3dce862320ab0f4a78255f740f7381396ab8d55f80c1b38a149"
       "f2418a2747795b44b14092fa17d215ae0e33c78997471ab971628b897776a80bbdee7e"
       "ddf60eca6cecba50f32281",
       /*.p_hex_str=*/
       "00e3f152467849f4c2d87f5a6506453878b7547996b14067966e336399e2be6a8c2ea8"
       "f065251f05e8bdcde4733d7084523432f3aad6b75990efadbedbce91cb097ce2b85dfa"
       "22fd3ca12a86198d76d31009531351f07246937cd7b1d81d3675f8afd759d1279edb13"
       "06e12f757baf368e265fb429775b1b4d16d88a7b009f00c7",
       /*.q_hex_str=*/
       "00d32b57f3d29f741c33ccf95d98b93b4efd56af0f9bc98f9089d8761ecccf65e0ba7f"
       "eebfbef8fce3bb38a4a5f9614d47a28f137238518ab47f0a12912dc951b1d540632bc5"
       "70338b17ee4f866767b7ba98ac6a057f1a2b27101ee584e9e82d4a83f31ef14d11f1d9"
       "105dc38e3052a506982ff3679e760c7ad186f361284c9069",
       /*.dp_hex_str=*/
       "00c536bf9694f077c2350a4aad69756e5c9351953959f67d295c033e43a0385b7b19cb"
       "b4e1edf21f6cb4fb7492782fe76c30197d54ec1d0a7329cbcb7be607a2017d79b3462b"
       "eb25ead50e33a3dc0f58a1614fed4151a5ad8661d744d9d4bc8fe9304a443d7fe82367"
       "1ce6abe71bb206a38a73f72e8143e4251885159b42784f75",
       /*.dq_hex_str=*/
       "367023116147e807e936bb466cbbbbd5662bf59f617af9beba3a8a60f04dbb26cf0d72"
       "000e7c63bd55a389969c0e807caa24964fc8c304adf95e20613adb7e6b08ddbb732a47"
       "fd91ab0ead83a99eac57b74a235edd6062a5845b62b1fc16f5ae130c16fafff25355b1"
       "096b0379e3a45569e05ab068c267ff358ac3ad55553f99",
       /*.coefficient_hex_str=*/
       "3a47030f3e868a1457f0290ae5e8e1a95fef23f9b8d90b20d8e75d138c94bc01e9922d"
       "60126a8af6c7142ebb32ced086b52cf1fa5dd389bce61bf6c66ec4c9d47cd08a8b5aad"
       "7d9f48202003cc19bdce05d1e41b568e60c43aec44a23031282bd46ac47ea77ddf2b8a"
       "303a784e27c73f9e0dd5b5f93e7be71361c2db675130d4",
       /*.public_pem=*/
       R"(-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvAZ+qQOMJLBjysYUayZ5
NJnMipOYUghZa5cArNTlGlgEEzFsxazFtJnUeBQhupsNivda5WthedWn/CCY8vxN
NmpqQWaxXyJU2xyzzl3Uq4C9i9Wttd80tgLDGdTQBCmcBuXiQ3/WJuKEwp7redGC
C4MLcGBy76L9HIiY0eqvOfufVM52ceorVRKkKQ0+xYu0Fjmhm+ZjCxwnBZuaMlBb
68b0KzAfn7LPK2JMG2WYcCu+rtOLX9mUHWYf9q3KZf+yUdHzFLztCGH6MOxnbiEp
5ay6A6bLdZT5PGDO+bKu7kXtxqrdMfhB7h83/WPM/zzruwGKPWMbPUmKeTSHBLtB
nwIDAQAB
-----END PUBLIC KEY-----)",
       /*.private_pem=*/
       R"(-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC8Bn6pA4wksGPK
xhRrJnk0mcyKk5hSCFlrlwCs1OUaWAQTMWzFrMW0mdR4FCG6mw2K91rla2F51af8
IJjy/E02ampBZrFfIlTbHLPOXdSrgL2L1a213zS2AsMZ1NAEKZwG5eJDf9Ym4oTC
nut50YILgwtwYHLvov0ciJjR6q85+59UznZx6itVEqQpDT7Fi7QWOaGb5mMLHCcF
m5oyUFvrxvQrMB+fss8rYkwbZZhwK76u04tf2ZQdZh/2rcpl/7JR0fMUvO0IYfow
7GduISnlrLoDpst1lPk8YM75sq7uRe3Gqt0x+EHuHzf9Y8z/POu7AYo9Yxs9SYp5
NIcEu0GfAgMBAAECggEAcYsagcX6o01BdfoX6nzZRMJ7mlN28FLKbQZLChOmJjpw
e4alQNoMqfsbK0g89gscKoclBNXLj19OihrFQjbKCcpJUCVLhz+cLpUun7hZ7RdZ
X1AyDloz4pXYa4jv9ROLfT7lXA2erOytbzm4yV+TQJBqH/qebcfnQYvbfShTmJcp
fH2lNYhn5g3+jHb79aakwGTg9q8b88lkDL7gB66jvoEBe3JtCItplXuET5UfrDI/
8+ef1n2vMqPc6GIyCrD0p4JV90D3OBOWq41V+AwbOKFJ8kGKJ0d5W0SxQJL6F9IV
rg4zx4mXRxq5cWKLiXd2qAu97n7d9g7KbOy6UPMigQKBgQDj8VJGeEn0wth/WmUG
RTh4t1R5lrFAZ5ZuM2OZ4r5qjC6o8GUlHwXovc3kcz1whFI0MvOq1rdZkO+tvtvO
kcsJfOK4Xfoi/TyhKoYZjXbTEAlTE1HwckaTfNex2B02dfiv11nRJ57bEwbhL3V7
rzaOJl+0KXdbG00W2Ip7AJ8AxwKBgQDTK1fz0p90HDPM+V2YuTtO/VavD5vJj5CJ
2HYezM9l4Lp/7r+++PzjuzikpflhTUeijxNyOFGKtH8KEpEtyVGx1UBjK8VwM4sX
7k+GZ2e3upisagV/GisnEB7lhOnoLUqD8x7xTRHx2RBdw44wUqUGmC/zZ552DHrR
hvNhKEyQaQKBgQDFNr+WlPB3wjUKSq1pdW5ck1GVOVn2fSlcAz5DoDhbexnLtOHt
8h9stPt0kngv52wwGX1U7B0KcynLy3vmB6IBfXmzRivrJerVDjOj3A9YoWFP7UFR
pa2GYddE2dS8j+kwSkQ9f+gjZxzmq+cbsgajinP3LoFD5CUYhRWbQnhPdQKBgDZw
IxFhR+gH6Ta7Rmy7u9VmK/WfYXr5vro6imDwTbsmzw1yAA58Y71Vo4mWnA6AfKok
lk/IwwSt+V4gYTrbfmsI3btzKkf9kasOrYOpnqxXt0ojXt1gYqWEW2Kx/Bb1rhMM
Fvr/8lNVsQlrA3njpFVp4FqwaMJn/zWKw61VVT+ZAoGAOkcDDz6GihRX8CkK5ejh
qV/vI/m42Qsg2OddE4yUvAHpki1gEmqK9scULrsyztCGtSzx+l3TibzmG/bGbsTJ
1HzQiotarX2fSCAgA8wZvc4F0eQbVo5gxDrsRKIwMSgr1GrEfqd93yuKMDp4TifH
P54N1bX5PnvnE2HC22dRMNQ=
-----END PRIVATE KEY-----)"}};
}

class PemParserRsaTest : public Test {
 public:
  PemParserRsaTest() : rsa_(RSA_new()) {}

  void SetUp() override {
    // Create a new RSA key and output to PEM.
    ASSERT_THAT(rsa_, NotNull());

    internal::SslUniquePtr<BIGNUM> e(BN_new());
    ASSERT_THAT(e, NotNull());
    ASSERT_EQ(BN_set_word(e.get(), RSA_F4), 1);

    // Generate a 2048 bits RSA key pair.
    ASSERT_EQ(RSA_generate_key_ex(rsa_.get(), 2048, e.get(), /*cb=*/nullptr), 1)
        << internal::GetSslErrors();

    // Write keys to PEM.
    internal::SslUniquePtr<BIO> pub_key_pem_bio(BIO_new(BIO_s_mem()));
    internal::SslUniquePtr<BIO> prv_key_pem_bio(BIO_new(BIO_s_mem()));

    // Write in PEM format.
    ASSERT_EQ(PEM_write_bio_RSA_PUBKEY(pub_key_pem_bio.get(), rsa_.get()), 1)
        << internal::GetSslErrors();
    ASSERT_EQ(PEM_write_bio_RSAPrivateKey(prv_key_pem_bio.get(), rsa_.get(),
                                          /*enc=*/nullptr, /*kstr=*/nullptr,
                                          /*klen=*/0, /*cb=*/nullptr,
                                          /*u=*/nullptr),
              1)
        << internal::GetSslErrors();

    pem_rsa_pub_key_.resize(BIO_number_written(pub_key_pem_bio.get()));
    pem_rsa_prv_key_.resize(BIO_number_written(prv_key_pem_bio.get()));
    ASSERT_EQ(BIO_read(pub_key_pem_bio.get(), &pem_rsa_pub_key_[0],
                       BIO_number_written(pub_key_pem_bio.get())),
              BIO_number_written(pub_key_pem_bio.get()));
    ASSERT_EQ(BIO_read(prv_key_pem_bio.get(), &pem_rsa_prv_key_[0],
                       BIO_number_written(prv_key_pem_bio.get())),
              BIO_number_written(prv_key_pem_bio.get()));
  }

  // Utility function that sets expectations to test that `bn_str` equals `bn`.
  void ExpectBnEqual(absl::string_view bn_str, const BIGNUM *bn) {
    util::StatusOr<std::string> expected_bn_str =
        internal::BignumToString(bn, BN_num_bytes(bn));
    ASSERT_THAT(expected_bn_str.status(), IsOk());
    EXPECT_EQ(bn_str, *expected_bn_str);
  }

 protected:
  // PEM encoded 2048 bit RSA key pair.
  std::string pem_rsa_pub_key_;
  std::string pem_rsa_prv_key_;
  // Holds the RSA object.
  const internal::SslUniquePtr<RSA> rsa_;
};

// Corrupts `container` by modifying one the elements in the middle.
template <class ContainerType>
void Corrupt(ContainerType *container) {
  if (container->empty()) {
    return;
  }
  std::vector<char> corrupted(container->begin(), container->end());
  size_t pos = corrupted.size() / 2;
  corrupted[pos] ^= 1;
  container->assign(corrupted.begin(), corrupted.end());
}

// Test we can correctly parse an RSA public key.
TEST_F(PemParserRsaTest, ReadRsaPublicKey) {
  auto key = PemParser::ParseRsaPublicKey(
      absl::string_view(pem_rsa_pub_key_.data(), pem_rsa_pub_key_.size()));
  ASSERT_THAT(key.status(), IsOk()) << internal::GetSslErrors();

  // Verify exponent and modulus are correctly set.
  const BIGNUM *e_bn, *n_bn;
  RSA_get0_key(rsa_.get(), &n_bn, &e_bn, nullptr);
  ExpectBnEqual((*key)->e, e_bn);
  ExpectBnEqual((*key)->n, n_bn);
}

// Test we can correctly parse an RSA private key.
TEST_F(PemParserRsaTest, ReadRsaPrivatekey) {
  auto key_statusor = PemParser::ParseRsaPrivateKey(
      absl::string_view(pem_rsa_prv_key_.data(), pem_rsa_prv_key_.size()));
  ASSERT_THAT(key_statusor.status(), IsOk()) << internal::GetSslErrors();

  // Verify exponents and modulus.
  auto key = *std::move(key_statusor);
  const BIGNUM *e_bn, *n_bn, *d_bn;
  RSA_get0_key(rsa_.get(), &n_bn, &e_bn, &d_bn);
  ExpectBnEqual(key->e, e_bn);
  ExpectBnEqual(key->n, n_bn);

  ExpectBnEqual(util::SecretDataAsStringView(key->d), d_bn);
  // Verify private key factors.
  const BIGNUM *p_bn, *q_bn;
  RSA_get0_factors(rsa_.get(), &p_bn, &q_bn);

  ExpectBnEqual(util::SecretDataAsStringView(key->p), p_bn);
  ExpectBnEqual(util::SecretDataAsStringView(key->q), q_bn);
  // Verify CRT parameters.
  const BIGNUM *dp_bn, *dq_bn, *crt_bn;
  RSA_get0_crt_params(rsa_.get(), &dp_bn, &dq_bn, &crt_bn);

  ExpectBnEqual(util::SecretDataAsStringView(key->dp), dp_bn);
  ExpectBnEqual(util::SecretDataAsStringView(key->dq), dq_bn);
  ExpectBnEqual(util::SecretDataAsStringView(key->crt), crt_bn);
}

using ParametrizedPemParserRsaTest = TestWithParam<RsaKeyTestVector>;

TEST_P(ParametrizedPemParserRsaTest, WriteRsaPrivateKey) {
  RsaKeyTestVector test_vector = GetParam();
  internal::RsaPrivateKey key;
  key.n = absl::HexStringToBytes(test_vector.modulus_hex_str);
  key.e = absl::HexStringToBytes(test_vector.public_exponent_hex_str);

  key.d = util::SecretDataFromStringView(
      absl::HexStringToBytes(test_vector.private_exponent_hex_str));
  key.p = util::SecretDataFromStringView(
      absl::HexStringToBytes(test_vector.p_hex_str));
  key.q = util::SecretDataFromStringView(
      absl::HexStringToBytes(test_vector.q_hex_str));
  key.dp = util::SecretDataFromStringView(
      absl::HexStringToBytes(test_vector.dp_hex_str));
  key.dq = util::SecretDataFromStringView(
      absl::HexStringToBytes(test_vector.dq_hex_str));
  key.crt = util::SecretDataFromStringView(
      absl::HexStringToBytes(test_vector.coefficient_hex_str));

  util::StatusOr<std::string> pem_result = PemParser::WriteRsaPrivateKey(key);
  EXPECT_THAT(pem_result.status(), IsOk()) << internal::GetSslErrors();
  EXPECT_EQ(absl::StripAsciiWhitespace(*pem_result), test_vector.private_pem);
}

TEST_P(ParametrizedPemParserRsaTest, WriteRsaPublicKey) {
  RsaKeyTestVector test_vector = GetParam();
  internal::RsaPublicKey key;
  key.n = absl::HexStringToBytes(test_vector.modulus_hex_str);
  key.e = absl::HexStringToBytes(test_vector.public_exponent_hex_str);

  auto pem_result = PemParser::WriteRsaPublicKey(key);
  EXPECT_THAT(pem_result.status(), IsOk());
  EXPECT_EQ(absl::StripAsciiWhitespace(*pem_result), test_vector.public_pem);
}

INSTANTIATE_TEST_SUITE_P(ParametrizedPemParserRsaTests,
                         ParametrizedPemParserRsaTest,
                         ValuesIn(GetRsaKeyTestVectors()));

TEST_F(PemParserRsaTest, ReadRsaPublicKeyInvalid) {
  Corrupt(&pem_rsa_pub_key_);
  EXPECT_THAT(
      PemParser::ParseRsaPrivateKey(
          absl::string_view(pem_rsa_pub_key_.data(), pem_rsa_pub_key_.size()))
          .status(),
      Not(IsOk()));
}

TEST_F(PemParserRsaTest, ReadRsaPrivateKeyInvalid) {
  Corrupt(&pem_rsa_prv_key_);
  EXPECT_THAT(
      PemParser::ParseRsaPrivateKey(
          absl::string_view(pem_rsa_prv_key_.data(), pem_rsa_prv_key_.size()))
          .status(),
      Not(IsOk()));
}

using ParametrizedPemParserEcTest = TestWithParam<EcKeyTestVector>;

TEST_P(ParametrizedPemParserEcTest, ReadEcPublicKeySuccess) {
  EcKeyTestVector test_vector = GetParam();
  auto ecdsa_key = PemParser::ParseEcPublicKey(
      absl::StripAsciiWhitespace(test_vector.pub_pem));

  EXPECT_THAT(ecdsa_key.status(), IsOk()) << internal::GetSslErrors();

  auto x_hex_result = absl::BytesToHexString(ecdsa_key->get()->pub_x);
  auto y_hex_result = absl::BytesToHexString(ecdsa_key->get()->pub_y);
  EXPECT_EQ(test_vector.pub_x_hex_str, x_hex_result);
  EXPECT_EQ(test_vector.pub_y_hex_str, y_hex_result);
  EXPECT_EQ(test_vector.curve, ecdsa_key->get()->curve);
}

TEST_P(ParametrizedPemParserEcTest, ReadEcPrivateKeySuccess) {
  EcKeyTestVector test_vector = GetParam();
  util::StatusOr<std::unique_ptr<SubtleUtilBoringSSL::EcKey>> ecdsa_key =
      PemParser::ParseEcPrivateKey(
          absl::StripAsciiWhitespace(test_vector.priv_pem));

  EXPECT_THAT(ecdsa_key.status(), IsOk()) << internal::GetSslErrors();

  std::string x_hex = absl::BytesToHexString((*ecdsa_key)->pub_x);
  std::string y_hex = absl::BytesToHexString((*ecdsa_key)->pub_y);
  std::string priv_hex =
      absl::BytesToHexString(util::SecretDataAsStringView((*ecdsa_key)->priv));
  EXPECT_THAT(x_hex, Eq(test_vector.pub_x_hex_str));
  EXPECT_THAT(y_hex, Eq(test_vector.pub_y_hex_str));
  EXPECT_THAT(priv_hex, Eq(absl::AsciiStrToLower(test_vector.priv_hex_str)));
  EXPECT_THAT((*ecdsa_key)->curve, test_vector.curve);
}

TEST_P(ParametrizedPemParserEcTest, ReadEcPublicKeyInvalid) {
  EcKeyTestVector test_vector = GetParam();
  std::string corrupt_pem = test_vector.pub_pem;
  Corrupt(&corrupt_pem);

  auto ecdsa_key =
      PemParser::ParseEcPublicKey(absl::StripAsciiWhitespace(corrupt_pem));

  EXPECT_THAT(ecdsa_key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_P(ParametrizedPemParserEcTest, ReadEcPrivateKeyInvalid) {
  EcKeyTestVector test_vector = GetParam();
  std::string corrupt_pem = test_vector.pub_pem;
  Corrupt(&corrupt_pem);

  util::StatusOr<std::unique_ptr<SubtleUtilBoringSSL::EcKey>> ecdsa_key =
      PemParser::ParseEcPrivateKey(absl::StripAsciiWhitespace(corrupt_pem));

  EXPECT_THAT(ecdsa_key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}
TEST_P(ParametrizedPemParserEcTest, WriteEcPublicKeySucceeds) {
  EcKeyTestVector test_vector = GetParam();
  // Load an EcKey with the test vector.
  SubtleUtilBoringSSL::EcKey ec_key;
  ec_key.curve = test_vector.curve;
  ec_key.pub_x = absl::HexStringToBytes(test_vector.pub_x_hex_str);
  ec_key.pub_y = absl::HexStringToBytes(test_vector.pub_y_hex_str);
  ec_key.priv = util::SecretDataFromStringView(
      absl::HexStringToBytes(test_vector.priv_hex_str));

  // Check that converting the public key with WriteEcPublicKey() succeeds.
  util::StatusOr<std::string> pem_material =
      PemParser::WriteEcPublicKey(ec_key);
  ASSERT_THAT(pem_material.status(), IsOk()) << internal::GetSslErrors();
  EXPECT_EQ(absl::StripAsciiWhitespace(*pem_material),
            absl::StripAsciiWhitespace(test_vector.pub_pem));
}

TEST_P(ParametrizedPemParserEcTest, WriteEcPrivateKeySucceeds) {
  EcKeyTestVector test_vector = GetParam();
  // Load an EcKey with the test vector.
  SubtleUtilBoringSSL::EcKey ec_key;
  ec_key.curve = test_vector.curve;
  ec_key.pub_x = absl::HexStringToBytes(test_vector.pub_x_hex_str);
  ec_key.pub_y = absl::HexStringToBytes(test_vector.pub_y_hex_str);
  ec_key.priv = util::SecretDataFromStringView(
      absl::HexStringToBytes(test_vector.priv_hex_str));

  // Check that converting the private key with WriteEcPrivateKey() succeeds.
  util::StatusOr<std::string> pem_material =
      PemParser::WriteEcPrivateKey(ec_key);
  ASSERT_THAT(pem_material.status(), IsOk());
  EXPECT_EQ(absl::StripAsciiWhitespace(*pem_material),
            absl::StripAsciiWhitespace(test_vector.priv_pem));
}

INSTANTIATE_TEST_SUITE_P(ParametrizedPemParserEcTest,
                         ParametrizedPemParserEcTest,
                         ValuesIn(GetEcKeyTestVectors()));

TEST(PemParserEcTest, NewKeyWriteAndReadPublicKeySuccess) {
  util::StatusOr<SubtleUtilBoringSSL::EcKey> ec_key =
      SubtleUtilBoringSSL::GetNewEcKey(EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key.status(), IsOk());

  util::StatusOr<std::string> public_pem = PemParser::WriteEcPublicKey(*ec_key);
  ASSERT_THAT(public_pem.status(), IsOk());
  util::StatusOr<std::unique_ptr<SubtleUtilBoringSSL::EcKey>> public_key =
      PemParser::ParseEcPublicKey(*public_pem);
  EXPECT_THAT(public_key.status(), IsOk()) << internal::GetSslErrors();
  EXPECT_EQ((*public_key)->pub_x, ec_key->pub_x);
  EXPECT_EQ((*public_key)->pub_y, ec_key->pub_y);
  EXPECT_EQ((*public_key)->curve, ec_key->curve);
}

TEST(PemParserEcTest, NewKeyWriteAndReadPrivateKeySuccess) {
  util::StatusOr<SubtleUtilBoringSSL::EcKey> ec_key =
      SubtleUtilBoringSSL::GetNewEcKey(EllipticCurveType::NIST_P256);
  ASSERT_THAT(ec_key.status(), IsOk());

  util::StatusOr<std::string> private_pem =
      PemParser::WriteEcPrivateKey(*ec_key);
  ASSERT_THAT(private_pem.status(), IsOk());
  util::StatusOr<std::unique_ptr<SubtleUtilBoringSSL::EcKey>> parsed_ec_key =
      PemParser::ParseEcPrivateKey(*private_pem);
  EXPECT_THAT(parsed_ec_key.status(), IsOk()) << internal::GetSslErrors();

  EXPECT_EQ((*parsed_ec_key)->pub_x, ec_key->pub_x);
  EXPECT_EQ((*parsed_ec_key)->pub_y, ec_key->pub_y);
  EXPECT_EQ((*parsed_ec_key)->priv, ec_key->priv);
  EXPECT_EQ((*parsed_ec_key)->curve, ec_key->curve);
}

TEST(PemParserEcTest, ReadEcPublicKeyP224_Unimplemented) {
  constexpr absl::string_view kP224PublicKey =
      R"(-----BEGIN PUBLIC KEY-----
ME4wEAYHKoZIzj0CAQYFK4EEACEDOgAE9PcDd+z3cVYhKnNbDVAXwDmShKBCPc88
sEUoYDu3Oi24YuZAFbwVIdX69RME4FB5PbxISleynMI=
-----END PUBLIC KEY-----)";

  auto ecdsa_key =
      PemParser::ParseEcPublicKey(absl::StripAsciiWhitespace(kP224PublicKey));

  EXPECT_THAT(ecdsa_key.status(), StatusIs(absl::StatusCode::kUnimplemented));
}

TEST(PemParserEcTest, ReadInvalidEcPublicKey) {
  util::StatusOr<std::unique_ptr<SubtleUtilBoringSSL::EcKey>> ecdsa_key =
      PemParser::ParseEcPublicKey("invalid");

  EXPECT_THAT(ecdsa_key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserEcTest, ReadInvalidEcPrivateKey) {
  util::StatusOr<std::unique_ptr<SubtleUtilBoringSSL::EcKey>> ecdsa_key =
      PemParser::ParseEcPrivateKey("invalid");

  EXPECT_THAT(ecdsa_key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

// Makes sure parsing of a valid EC public key on secp256k1 fails because the
// curve is unsupported.
TEST(PemParserEcTest, ReadEcPublicKeyFailsBecauseSecp256k1Unsupported) {
  // Generate private key with:
  // > openssl ecparam -genkey -name secp256k1 -noout -out ec-key-pair.pem
  // Extract the public key:
  // > openssl ec -in ec-key-pair.pem -pubout
  constexpr absl::string_view kSecp256k1PublicKey =
      R"(-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEC9naJNDkHKVBjfDK90szJegpzatlUcFO
BLrJS8EVf4tMw52zdhXpKBF2FGpD54dNo+Ut2s6JIE+LoaX/FSvifw==
-----END PUBLIC KEY-----)";

  util::StatusOr<std::unique_ptr<SubtleUtilBoringSSL::EcKey>> ecdsa_key =
      PemParser::ParseEcPublicKey(
          absl::StripAsciiWhitespace(kSecp256k1PublicKey));
  // With BoringSSL parsing of the PEM key fails when an unsupported curve is
  // used [1]; Supported curves are defined here [2]. Tink doesn't distinguish
  // between an error caused by a malformed PEM and an unsupported group by
  // BoringSSL. On the other hand, with OpenSSL parsing succeeds, but this
  // curve is unsupported by Tink. As a consequence, this fails with two
  // different errors.
  //
  // [1]https://github.com/google/boringssl/blob/master/crypto/ec_extra/ec_asn1.c#L324
  // [2]https://github.com/google/boringssl/blob/master/crypto/fipsmodule/ec/ec.c#L218
  if (internal::IsBoringSsl()) {
    EXPECT_THAT(ecdsa_key.status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  } else {
    EXPECT_THAT(ecdsa_key.status(), StatusIs(absl::StatusCode::kUnimplemented));
  }
}

// Makes sure parsing of a valid EC private key on secp256k1 fails because the
// curve is unsupported.
TEST(PemParserEcTest, ReadEcPrivateKeyFailsBecauseSecp256k1Unsupported) {
  // Generate private key with:
  // > openssl ecparam -genkey -name secp256k1 -noout
  constexpr absl::string_view kSecp256k1PrivateKey =
      R"(-----BEGIN EC PRIVATE KEY-----
MHQCAQEEIKSqexQyySWB705oPctFx2roLMHdfJ/W/WBISaRNu1UHoAcGBSuBBAAK
oUQDQgAEC9naJNDkHKVBjfDK90szJegpzatlUcFOBLrJS8EVf4tMw52zdhXpKBF2
FGpD54dNo+Ut2s6JIE+LoaX/FSvifw==
-----END EC PRIVATE KEY-----)";

  util::StatusOr<std::unique_ptr<SubtleUtilBoringSSL::EcKey>> ecdsa_key =
      PemParser::ParseEcPrivateKey(
          absl::StripAsciiWhitespace(kSecp256k1PrivateKey));

  // PEM parsing fails in BoringSSL when the curve is unsupported, and Tink
  // doesn't distinguish between an error caused by a malformed PEM and an
  // unsupported group by BoringSSL. With OpenSSL parsing succeeds, but this
  // curve is unsupported by Tink. As a consequence, this fails with two
  // different errors.
  if (internal::IsBoringSsl()) {
    EXPECT_THAT(ecdsa_key.status(),
                StatusIs(absl::StatusCode::kInvalidArgument));
  } else {
    EXPECT_THAT(ecdsa_key.status(), StatusIs(absl::StatusCode::kUnimplemented));
  }
}

TEST(PemParserEcTest, ParseEncryptedEcPrivateKey_Invalid) {
  // This key was generated with the command:
  // openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:prime256v1
  // -aes128 using pass phrase "mypassword"
  constexpr absl::string_view kPrivateKey =
      R"(-----BEGIN ENCRYPTED PRIVATE KEY-----
MIHsMFcGCSqGSIb3DQEFDTBKMCkGCSqGSIb3DQEFDDAcBAjurwMnDwdrOwICCAAw
DAYIKoZIhvcNAgkFADAdBglghkgBZQMEAQIEEJHshE1SbT5XZN1bToPLsuAEgZAA
xmCJjv1kTjWzwbE1SEM6lwMippywDf0JH+de4JwlrPiQAb5NExq96m6Per70tX4W
iJ76WplZagsJzsAg/5gIJ/YcTry266rP2SBVTsuCY/GOh2vU/x6XFbPi9JCM0nvH
GTi1cWyqIwzGqfw8ZGejtvg4SAGulZ7/MWVCZV51C6JakfY1v3z24BQG1m50jMs=
-----END ENCRYPTED PRIVATE KEY-----)";

  util::StatusOr<std::unique_ptr<SubtleUtilBoringSSL::EcKey>> ecdsa_key =
      PemParser::ParseEcPrivateKey(absl::StripAsciiWhitespace(kPrivateKey));

  EXPECT_THAT(ecdsa_key.status(), StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(PemParserEcTest, WriteEcPublicKeyWithBadXFails) {
  util::StatusOr<SubtleUtilBoringSSL::EcKey> ec_key_statusor =
      SubtleUtilBoringSSL::GetNewEcKey(subtle::NIST_P256);
  ASSERT_THAT(ec_key_statusor.status(), IsOk());
  SubtleUtilBoringSSL::EcKey ec_key = *ec_key_statusor;
  Corrupt(&ec_key.pub_x);
  // Bad coordinates should generate a BoringSSL/OpenSSL's internal error.
  EXPECT_THAT(PemParser::WriteEcPublicKey(ec_key).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(PemParserEcTest, WriteEcPublicKeyWithBadYFails) {
  util::StatusOr<SubtleUtilBoringSSL::EcKey> ec_key_statusor =
      SubtleUtilBoringSSL::GetNewEcKey(subtle::NIST_P256);
  ASSERT_THAT(ec_key_statusor.status(), IsOk());
  SubtleUtilBoringSSL::EcKey ec_key = *ec_key_statusor;
  Corrupt(&ec_key.pub_y);
  EXPECT_THAT(PemParser::WriteEcPublicKey(ec_key).status(),
              StatusIs(absl::StatusCode::kInternal));
}

TEST(PemParserEcTest, WriteEcPrivateKeyWithBadPrivFails) {
  util::StatusOr<SubtleUtilBoringSSL::EcKey> ec_key_statusor =
      SubtleUtilBoringSSL::GetNewEcKey(subtle::NIST_P256);
  ASSERT_THAT(ec_key_statusor.status(), IsOk());
  SubtleUtilBoringSSL::EcKey ec_key = *ec_key_statusor;
  std::string priv = std::string(util::SecretDataAsStringView(ec_key.priv));
  Corrupt(&priv);
  ec_key.priv = util::SecretDataFromStringView(priv);
  EXPECT_THAT(PemParser::WriteEcPrivateKey(ec_key).status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
