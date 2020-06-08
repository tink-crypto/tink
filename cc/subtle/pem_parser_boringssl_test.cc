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

#include <memory>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "openssl/base.h"
#include "openssl/bio.h"
#include "openssl/bn.h"
#include "openssl/evp.h"
#include "openssl/pem.h"
#include "openssl/rsa.h"
#include "tink/subtle/subtle_util_boringssl.h"
#include "tink/util/secret_data.h"
#include "tink/util/status.h"
#include "tink/util/statusor.h"
#include "tink/util/test_matchers.h"
#include "tink/util/test_util.h"

namespace crypto {
namespace tink {
namespace subtle {
namespace {

using ::crypto::tink::test::StatusIs;

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

static const auto *kEcKeyTestVectors = new std::vector<EcKeyTestVector>({
    // NIST P256
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

    // NIST P384
    {
        /*.curve=*/subtle::NIST_P384,
        /*.pub_x_hex_str=*/
        "49b1a78537281c81984e00092f04c22c610cac2aba7a3de992bf6ad22305d2d5450187"
        "57ed823c643334e18d95b2e642",
        /*.pub_y_hex_str=*/
        "d2a851445c5da0bf0d543eaad5ff98634483c549d96045243121ed6d5c9ba64dab656a"
        "6d25e018b01c4d3ab3f1738989",
        /*.priv_hex_str=*/
        "0254cd5840eec13b0d68ba08fdbc147c22906046ecb2fca2625294be74dea29aa370fd"
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
        "82de2530a8d589149c8a60fdd529ed7a465db62d7412771a7ec40a69be139226b60906"
        "cc784007d8e28a79dca528e66c",
        /*.pub_y_hex_str=*/
        "c41f7532b8325aad3f1dddebddb702ebe70259bb5730e6bc4a75baec0d85c52d0d00c8"
        "e372d1da0d1ca10136e4cfd262",
        /*.priv_hex_str=*/
        "a6a8415b526418966758cfda45c19b4fe0ac4cf06d301b195ffea231d0eda67a54fb7c"
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

    // NIST P521
    {
        /*.curve=*/subtle::NIST_P521,
        /*.pub_x_hex_str=*/
        "01d09ee2f33ce601d8594b09e668e128a7708ce752ef589d1a2c405523db0b68a0cb58"
        "60359b12c5371fc462f4142339ca7ff2550833f0a64887951ddb64e7d139d5",
        /*.pub_y_hex_str=*/
        "01b45ce12804afcf17fbd60728d362d4787b750d561e52144fd517807ddaa2b396bed9"
        "98227a5696d9c997a1cf0b6f1a3724ce25c7396dc2ea62c4bdf467061916e3",
        /*.priv_hex_str=*/
        "01f1913a921271c06686482a51dbf2c853aefbcc62b2b23d473a4c818d570e55566742"
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
        "0108803f92f8449fdfca02c8c2b49643f407f63dda728ad38e3598b887b5831ab063d9"
        "60c5fd321ee597f4273fc0596015ce406515a2ab24a7c96a44802d74c3ac7b",
        /*.pub_y_hex_str=*/
        "01f216dc0f590b920d9c026e0aedc2b1cfe85d4f2d607db632395c7f64c05328593633"
        "635b6ad8bf51d2ee70c88000e96fd340601211c1d1eb0b32773806506b47b0",
        /*.priv_hex_str=*/
        "0010a207e650cf531c98c0c6d1cfdb88a5ee57f02734cbab93b8ae30d9dac0845d1761"
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
});

class PemParserTest : public ::testing::Test {
 public:
  PemParserTest() : rsa_(RSA_new()) {}

  void SetUp() override {
    // Create a new RSA key and output to PEM.
    ASSERT_THAT(rsa_, testing::NotNull());

    bssl::UniquePtr<BIGNUM> e(BN_new());
    ASSERT_THAT(e, testing::NotNull());
    BN_set_word(e.get(), RSA_F4);

    // Generate a 2048 bits RSA key pair.
    EXPECT_EQ(RSA_generate_key_ex(rsa_.get(), 2048, e.get(), /*cb=*/nullptr), 1)
        << SubtleUtilBoringSSL::GetErrors();

    // Write keys to PEM.
    bssl::UniquePtr<BIO> pub_key_pem_bio(BIO_new(BIO_s_mem()));
    bssl::UniquePtr<BIO> prv_key_pem_bio(BIO_new(BIO_s_mem()));

    // Write in PEM format.
    EXPECT_EQ(PEM_write_bio_RSA_PUBKEY(pub_key_pem_bio.get(), rsa_.get()), 1)
        << SubtleUtilBoringSSL::GetErrors();
    EXPECT_EQ(
        PEM_write_bio_RSAPrivateKey(prv_key_pem_bio.get(), rsa_.get(),
                                    /*enc=*/nullptr, /*kstr=*/nullptr,
                                    /*klen=*/0, /*cb=*/nullptr, /*u=*/nullptr),
        1)
        << SubtleUtilBoringSSL::GetErrors();

    pem_rsa_pub_key_.resize(pub_key_pem_bio->num_write + 1);
    pem_rsa_prv_key_.resize(prv_key_pem_bio->num_write + 1);
    EXPECT_EQ(BIO_read(pub_key_pem_bio.get(), pem_rsa_pub_key_.data(),
                       pub_key_pem_bio->num_write),
              pub_key_pem_bio->num_write);
    EXPECT_EQ(BIO_read(prv_key_pem_bio.get(), pem_rsa_prv_key_.data(),
                       prv_key_pem_bio->num_write),
              prv_key_pem_bio->num_write);
  }

 protected:
  // PEM encoded 2048 bit RSA key pair.
  std::vector<char> pem_rsa_pub_key_;
  std::vector<char> pem_rsa_prv_key_;

  // Holds the RSA object.
  bssl::UniquePtr<RSA> rsa_;
};

// Corrupts `container` by modifying one the elements in the middle.
template <class ContainerType>
void Corrupt(ContainerType* container) {
  if (container->empty()) {
    return;
  }
  std::vector<char> corrupted(container->begin(), container->end());
  size_t pos = corrupted.size() / 2;
  corrupted[pos] ^= 1;
  container->assign(corrupted.begin(), corrupted.end());
}

// Test we can correctly parse an RSA public key.
TEST_F(PemParserTest, ReadRsaPublicKey) {
  auto key_statusor = PemParser::ParseRsaPublicKey(
      absl::string_view(pem_rsa_pub_key_.data(), pem_rsa_pub_key_.size()));
  ASSERT_TRUE(key_statusor.ok()) << SubtleUtilBoringSSL::GetErrors();

  // Verify exponent and modulus are correctly set.
  auto key = std::move(key_statusor.ValueOrDie());
  const BIGNUM *e_bn, *n_bn;
  RSA_get0_key(rsa_.get(), &n_bn, &e_bn, nullptr);
  EXPECT_EQ(key->e,
            SubtleUtilBoringSSL::bn2str(e_bn, BN_num_bytes(e_bn)).ValueOrDie());
  EXPECT_EQ(key->n,
            SubtleUtilBoringSSL::bn2str(n_bn, BN_num_bytes(n_bn)).ValueOrDie());
}

// Test we can correctly parse an RSA private key.
TEST_F(PemParserTest, ReadRsaPrivatekey) {
  auto key_statusor = PemParser::ParseRsaPrivateKey(
      absl::string_view(pem_rsa_prv_key_.data(), pem_rsa_prv_key_.size()));
  ASSERT_TRUE(key_statusor.ok()) << SubtleUtilBoringSSL::GetErrors();

  // Verify exponents and modulus.
  auto key = std::move(key_statusor.ValueOrDie());
  const BIGNUM *e_bn, *n_bn, *d_bn;
  RSA_get0_key(rsa_.get(), &n_bn, &e_bn, &d_bn);
  EXPECT_EQ(key->e,
            SubtleUtilBoringSSL::bn2str(e_bn, BN_num_bytes(e_bn)).ValueOrDie());
  EXPECT_EQ(key->n,
            SubtleUtilBoringSSL::bn2str(n_bn, BN_num_bytes(n_bn)).ValueOrDie());
  EXPECT_EQ(util::SecretDataAsStringView(key->d),
            SubtleUtilBoringSSL::bn2str(d_bn, BN_num_bytes(d_bn)).ValueOrDie());
  // Verify private key factors.
  const BIGNUM *p_bn, *q_bn;
  RSA_get0_factors(rsa_.get(), &p_bn, &q_bn);
  EXPECT_EQ(util::SecretDataAsStringView(key->p),
            SubtleUtilBoringSSL::bn2str(p_bn, BN_num_bytes(p_bn)).ValueOrDie());
  EXPECT_EQ(util::SecretDataAsStringView(key->q),
            SubtleUtilBoringSSL::bn2str(q_bn, BN_num_bytes(q_bn)).ValueOrDie());
  // Verify CRT parameters.
  const BIGNUM *dp_bn, *dq_bn, *crt_bn;
  RSA_get0_crt_params(rsa_.get(), &dp_bn, &dq_bn, &crt_bn);
  EXPECT_EQ(
      util::SecretDataAsStringView(key->dp),
      SubtleUtilBoringSSL::bn2str(dp_bn, BN_num_bytes(dp_bn)).ValueOrDie());
  EXPECT_EQ(
      util::SecretDataAsStringView(key->dq),
      SubtleUtilBoringSSL::bn2str(dq_bn, BN_num_bytes(dq_bn)).ValueOrDie());
  EXPECT_EQ(
      util::SecretDataAsStringView(key->crt),
      SubtleUtilBoringSSL::bn2str(crt_bn, BN_num_bytes(crt_bn)).ValueOrDie());
}

TEST_F(PemParserTest, ReadRsaPublicKeyInvalid) {
  Corrupt(&pem_rsa_pub_key_);
  EXPECT_TRUE(
      !PemParser::ParseRsaPrivateKey(
           absl::string_view(pem_rsa_pub_key_.data(), pem_rsa_pub_key_.size()))
           .ok());
}

TEST_F(PemParserTest, ReadRsaPrivateKeyInvalid) {
  Corrupt(&pem_rsa_prv_key_);
  EXPECT_TRUE(
      !PemParser::ParseRsaPrivateKey(
           absl::string_view(pem_rsa_prv_key_.data(), pem_rsa_prv_key_.size()))
           .ok());
}

TEST_F(PemParserTest, WriteEcPublicKeySucceeds) {
  for (const auto& test_vector : *kEcKeyTestVectors) {
    // Load an EcKey with the test vector.
    SubtleUtilBoringSSL::EcKey ec_key;
    ec_key.curve = test_vector.curve;
    ec_key.pub_x = absl::HexStringToBytes(test_vector.pub_x_hex_str);
    ec_key.pub_y = absl::HexStringToBytes(test_vector.pub_y_hex_str);
    ec_key.priv = util::SecretDataFromStringView(
        absl::HexStringToBytes(test_vector.priv_hex_str));

    // Check that converting the public key with WriteEcPublicKey() succeeds.
    auto pem_material_statusor = PemParser::WriteEcPublicKey(ec_key);
    ASSERT_TRUE(pem_material_statusor.ok()) << pem_material_statusor.status();
    std::string pem_material = pem_material_statusor.ValueOrDie();
    EXPECT_TRUE(absl::StripAsciiWhitespace(pem_material) ==
                absl::StripAsciiWhitespace(test_vector.pub_pem));
  }
}

TEST_F(PemParserTest, WriteEcPrivateKeySucceeds) {
  for (const auto& test_vector : *kEcKeyTestVectors) {
    // Load an EcKey with the test vector.
    SubtleUtilBoringSSL::EcKey ec_key;
    ec_key.curve = test_vector.curve;
    ec_key.pub_x = absl::HexStringToBytes(test_vector.pub_x_hex_str);
    ec_key.pub_y = absl::HexStringToBytes(test_vector.pub_y_hex_str);
    ec_key.priv = util::SecretDataFromStringView(
        absl::HexStringToBytes(test_vector.priv_hex_str));

    // Check that converting the private key with WriteEcPrivateKey() succeeds.
    auto pem_material_statusor = PemParser::WriteEcPrivateKey(ec_key);
    ASSERT_TRUE(pem_material_statusor.ok()) << pem_material_statusor.status();
    std::string pem_material = pem_material_statusor.ValueOrDie();
    EXPECT_TRUE(absl::StripAsciiWhitespace(pem_material) ==
                absl::StripAsciiWhitespace(test_vector.priv_pem));
  }
}

TEST_F(PemParserTest, WriteEcPublicKeyWithBadXFails) {
  auto ec_key_statusor = SubtleUtilBoringSSL::GetNewEcKey(subtle::NIST_P256);
  ASSERT_TRUE(ec_key_statusor.ok()) << ec_key_statusor.status();
  SubtleUtilBoringSSL::EcKey ec_key = ec_key_statusor.ValueOrDie();
  Corrupt(&ec_key.pub_x);
  EXPECT_THAT(PemParser::WriteEcPublicKey(ec_key).status(),
              StatusIs(util::error::INVALID_ARGUMENT));
}

TEST_F(PemParserTest, WriteEcPublicKeyWithBadYFails) {
  auto ec_key_statusor = SubtleUtilBoringSSL::GetNewEcKey(subtle::NIST_P256);
  ASSERT_TRUE(ec_key_statusor.ok()) << ec_key_statusor.status();
  SubtleUtilBoringSSL::EcKey ec_key = ec_key_statusor.ValueOrDie();
  Corrupt(&ec_key.pub_y);
  EXPECT_THAT(PemParser::WriteEcPublicKey(ec_key).status(),
              StatusIs(util::error::INVALID_ARGUMENT));
}

TEST_F(PemParserTest, WriteEcPrivateKeyWithBadPrivFails) {
  auto ec_key_statusor = SubtleUtilBoringSSL::GetNewEcKey(subtle::NIST_P256);
  ASSERT_TRUE(ec_key_statusor.ok()) << ec_key_statusor.status();
  SubtleUtilBoringSSL::EcKey ec_key = ec_key_statusor.ValueOrDie();
  std::string priv = std::string(util::SecretDataAsStringView(ec_key.priv));
  Corrupt(&priv);
  ec_key.priv = util::SecretDataFromStringView(priv);
  EXPECT_THAT(PemParser::WriteEcPrivateKey(ec_key).status(),
              StatusIs(util::error::INVALID_ARGUMENT));
}

}  // namespace
}  // namespace subtle
}  // namespace tink
}  // namespace crypto
