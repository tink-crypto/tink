# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Tests for tink.python.tink.jwt._jwk_set_converter."""

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import cleartext_keyset_handle
from tink import jwt

ES256_KEYSET = (
    '{"primaryKeyId":282600252,"key":[{"keyData":{'
    '"typeUrl":"type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",'
    '"value":"EAEaIBDPI66hjLHvjxmUJ2nyHIBDmdOtQ4gPsvWgYYgZ0gygIiBTEK0rTACpAb97m'
    '+mvtJKAk0q3mHjPcUZm0C4EueDW4Q==",'
    '"keyMaterialType":"ASYMMETRIC_PUBLIC"'
    '},"status":"ENABLED","keyId":282600252,"outputPrefixType":"RAW"}]}')

ES256_JWK_SET = ('{"keys":[{'
                 '"kty":"EC",'
                 '"crv":"P-256",'
                 '"x":"EM8jrqGMse-PGZQnafIcgEOZ061DiA-y9aBhiBnSDKA",'
                 '"y":"UxCtK0wAqQG_e5vpr7SSgJNKt5h4z3FGZtAuBLng1uE",'
                 '"use":"sig","alg":"ES256","key_ops":["verify"]}]}')

ES256_KEYSET_TINK = (
    '{"primaryKeyId":282600252,"key":[{"keyData":{'
    '"typeUrl":"type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",'
    '"value":"EAEaIBDPI66hjLHvjxmUJ2nyHIBDmdOtQ4gPsvWgYYgZ0gygIiBTEK0rTACpAb97m'
    '+mvtJKAk0q3mHjPcUZm0C4EueDW4Q==",'
    '"keyMaterialType":"ASYMMETRIC_PUBLIC"'
    '},"status":"ENABLED","keyId":282600252,"outputPrefixType":"TINK"}]}')

ES256_JWK_SET_KID = ('{"keys":[{'
                     '"kty":"EC",'
                     '"crv":"P-256",'
                     '"x":"EM8jrqGMse-PGZQnafIcgEOZ061DiA-y9aBhiBnSDKA",'
                     '"y":"UxCtK0wAqQG_e5vpr7SSgJNKt5h4z3FGZtAuBLng1uE",'
                     '"use":"sig","alg":"ES256","key_ops":["verify"],'
                     '"kid":"ENgjPA"}]}')

ES384_KEYSET = (
    '{"primaryKeyId":456087424,"key":[{"keyData":{'
    '"typeUrl":"type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",'
    '"value":"EAIaMQDSjvWihoKGmr4nlDuI/KkvuPvEZr+B4bU0MuXQQXgyNMGApFm2iTeotv7LC'
    'SsG3mQiMEHIMGx4wa+Y8yeJQWMiSpukpPM7jP9GqaykZQQ2GY/NLg/n9+BJtntgvFhG5gWLTg='
    '=","keyMaterialType":"ASYMMETRIC_PUBLIC"'
    '},"status":"ENABLED","keyId":456087424,"outputPrefixType":"RAW"}]}')

ES384_JWK_SET = (
    '{"keys":[{"kty":"EC","crv":"P-384",'
    '"x":"ANKO9aKGgoaavieUO4j8qS-4-8Rmv4HhtTQy5dBBeDI0wYCkWbaJN6i2_ssJKwbeZA",'
    '"y":"QcgwbHjBr5jzJ4lBYyJKm6Sk8zuM_0aprKRlBDYZj80uD-f34Em2e2C8WEbmBYtO",'
    '"use":"sig","alg":"ES384","key_ops":["verify"]}]}')

ES512_KEYSET = (
    '{"primaryKeyId":1570200439,"key":[{"keyData":{'
    '"typeUrl":"type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",'
    '"value":"EAMaQgEV3nweRej6Z1/aPTqCkc1tQla5eVI68+qfwR1kB/wXCuYCB5otarhomUt64'
    'Fah/8Tjf0WJHMZyFr86RUitiRQm1SJCATht/NOX8RcbaEr1MaH+0BFTaepvpTzSfQ04C2P8VCo'
    'URB3GeVKk4VQh8O/KLSYfX+58bqEnaZ0G7W9qjHa2ols2",'
    '"keyMaterialType":"ASYMMETRIC_PUBLIC"'
    '},"status":"ENABLED","keyId":1570200439,"outputPrefixType":"RAW"}]}')

ES512_JWK_SET = (
    '{"keys":[{"kty":"EC","crv":"P-521",'
    '"x":"ARXefB5F6PpnX9o9OoKRzW1CVrl5Ujrz6p_BHWQH_BcK5gIHmi1quGiZS3rgVqH_xON_R'
    'YkcxnIWvzpFSK2JFCbV",'
    '"y":"ATht_NOX8RcbaEr1MaH-0BFTaepvpTzSfQ04C2P8VCoURB3GeVKk4VQh8O_KLSYfX-58b'
    'qEnaZ0G7W9qjHa2ols2",'
    '"use":"sig","alg":"ES512","key_ops":["verify"]}]}')

RS256_KEYSET = (
    '{"primaryKeyId":482168993,"key":[{"keyData":{'
    '"typeUrl":"type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey"'
    ',"value":"EAEagQIAkspk37lGBqXmPPq2CL5KdDeRx7xFiTadpL3jc4nXaqftCtpM6qExfrc2'
    'JLaIsnwpwfGMClfe/alIs2GrT9fpM8oDeCccvC39DzZhsSFnAELggi3hnWNKRLfSV0UJzBI+5h'
    'Z6ifUsv8W8mSHKlsVMmvOfC2P5+l72qTwN6Le3hy6CxFp5s9pw011B7J3PU65sty6GI9sehB2B'
    '/n7nfiWw9YN5++pfwyoitzoMoVKOOpj7fFq88f8ArpC7kR1SBTe20Bt1AmpZDT2Dmfmlb/Q1UF'
    'jj/F3C77NCNQ344ZcAEI42HY+uighy5GdKQRHMoTT1OzyDG90ABjggQqDGW+zXzyIDAQAB",'
    '"keyMaterialType":"ASYMMETRIC_PUBLIC"'
    '},"status":"ENABLED","keyId":482168993,"outputPrefixType":"RAW"}]}')

PRIVATEKEY_KEYSET = (
    '{"primaryKeyId":152493399,"key":[{"keyData":{'
    '"typeUrl":"type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey",'
    '"value":"EkYQARogaHkaakArEB51RyZ236S5x3BxaNTFycWuXIGZF8adZ2UiIFlZT7MFogZ'
    '8ARbS1URIAPcpw8A0g2uwAHRkBqGUiCU2GiBI4jtU/59Zajohgeezi2BXB13O8IJh8V3b0it'
    'q5zyy5Q==",'
    '"keyMaterialType":"ASYMMETRIC_PRIVATE"'
    '},"status":"ENABLED","keyId":152493399,"outputPrefixType":"RAW"}]}')

KEYSET_WITH_DISABLED_KEY = (
    '{"primaryKeyId":282600252,"key":['
    '{"keyData":{'
    '"typeUrl":"type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey",'
    '"value":"EAEaIBDPI66hjLHvjxmUJ2nyHIBDmdOtQ4gPsvWgYYgZ0gygIiBTEK0rTACpAb97m'
    '+mvtJKAk0'
    'q3mHjPcUZm0C4EueDW4Q==",'
    '"keyMaterialType":"ASYMMETRIC_PUBLIC"'
    '},"status":"ENABLED","keyId":282600252,"outputPrefixType":"RAW"},'
    '{"keyData":{'
    '"typeUrl":"type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey"'
    ','
    '"value":"EAEagQIAkspk37lGBqXmPPq2CL5KdDeRx7xFiTadpL3jc4nXaqftCtpM6qExfrc2J'
    'LaIsnwpwfGMClfe/alIs2GrT9fpM8oDeCccvC39DzZhsSFnAELggi3hnWNKRLfSV0UJzBI+5hZ'
    '6ifUsv8W8mSHKlsVMmvOfC2P5+l72qTwN6Le3hy6CxFp5s9pw011B7J3PU65sty6GI9sehB2B/'
    'n7nfiWw9YN5++pfwyoitzoMoVKOOpj7fFq88f8ArpC7kR1SBTe20Bt1AmpZDT2Dmfmlb/Q1UFj'
    'j/F3C77NCNQ344ZcAEI42HY+uighy5GdKQRHMoTT1OzyDG90ABjggQqDGW+zXzyIDAQAB",'
    '"keyMaterialType":"ASYMMETRIC_PUBLIC"'
    '},"status":"DISABLED","keyId":482168993,"outputPrefixType":"RAW"}]}')


class JwkSetConverterTest(parameterized.TestCase):

  @parameterized.named_parameters([
      ('ES256_RAW', ES256_KEYSET, ES256_JWK_SET),
      ('ES384_RAW', ES384_KEYSET, ES384_JWK_SET),
      ('ES512_RAW', ES512_KEYSET, ES512_JWK_SET),
      ('WITH_DISABLED_KEY', KEYSET_WITH_DISABLED_KEY, ES256_JWK_SET),
      ('ES256_TINK', ES256_KEYSET_TINK, ES256_JWK_SET_KID)
  ])
  def test_convert_from_jwt_ecdsa_key(self, tink_keyset, expected_jwk_set):
    reader = tink.JsonKeysetReader(tink_keyset)
    keyset_handle = cleartext_keyset_handle.read(reader)
    jwk_set = jwt.jwk_set_from_keyset_handle(keyset_handle)
    self.assertEqual(jwk_set, expected_jwk_set)

  def test_primary_key_id_missing_success(self):
    keyset = ES256_KEYSET.replace('"primaryKeyId":282600252,', '')
    reader = tink.JsonKeysetReader(keyset)
    keyset_handle = cleartext_keyset_handle.read(reader)
    jwk_set = jwt.jwk_set_from_keyset_handle(keyset_handle)
    self.assertEqual(jwk_set, ES256_JWK_SET)

  def test_from_legacy_ecdsa_keyset_fails(self):
    keyset = ES256_KEYSET.replace('RAW', 'LEGACY')
    reader = tink.JsonKeysetReader(keyset)
    keyset_handle = cleartext_keyset_handle.read(reader)
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_from_keyset_handle(keyset_handle)

  def test_from_crunchy_ecdsa_keyset_fails(self):
    keyset = ES256_KEYSET.replace('RAW', 'CRUNCHY')
    reader = tink.JsonKeysetReader(keyset)
    keyset_handle = cleartext_keyset_handle.read(reader)
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_from_keyset_handle(keyset_handle)

  def test_from_rs256_keyset_fails(self):
    reader = tink.JsonKeysetReader(RS256_KEYSET)
    keyset_handle = cleartext_keyset_handle.read(reader)
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_from_keyset_handle(keyset_handle)

  def test_from_private_keyset_fails(self):
    reader = tink.JsonKeysetReader(PRIVATEKEY_KEYSET)
    keyset_handle = cleartext_keyset_handle.read(reader)
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_from_keyset_handle(keyset_handle)

if __name__ == '__main__':
  absltest.main()
