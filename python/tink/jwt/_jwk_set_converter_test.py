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

RS256_JWK_SET = (
    '{"keys":[{"kty":"RSA",'
    '"n":"AJLKZN-5Rgal5jz6tgi-SnQ3kce8RYk2naS943OJ12qn7QraTOqhMX63NiS2iLJ8KcHxj'
    'ApX3v2pSLNhq0_X6TPKA3gnHLwt_Q82YbEhZwBC4IIt4Z1jSkS30ldFCcwSPuYWeon1LL_FvJk'
    'hypbFTJrznwtj-fpe9qk8Dei3t4cugsRaebPacNNdQeydz1OubLcuhiPbHoQdgf5-534lsPWDe'
    'fvqX8MqIrc6DKFSjjqY-3xavPH_AK6Qu5EdUgU3ttAbdQJqWQ09g5n5pW_0NVBY4_xdwu-zQjU'
    'N-OGXABCONh2ProoIcuRnSkERzKE09Ts8gxvdAAY4IEKgxlvs188",'
    '"e":"AQAB","use":"sig","alg":"RS256","key_ops":["verify"]}]}')

RS256_KEYSET_TINK = (
    '{"primaryKeyId":482168993,"key":[{"keyData":{'
    '"typeUrl":"type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey"'
    ',"value":"EAEagQIAkspk37lGBqXmPPq2CL5KdDeRx7xFiTadpL3jc4nXaqftCtpM6qExfrc2'
    'JLaIsnwpwfGMClfe/alIs2GrT9fpM8oDeCccvC39DzZhsSFnAELggi3hnWNKRLfSV0UJzBI+5h'
    'Z6ifUsv8W8mSHKlsVMmvOfC2P5+l72qTwN6Le3hy6CxFp5s9pw011B7J3PU65sty6GI9sehB2B'
    '/n7nfiWw9YN5++pfwyoitzoMoVKOOpj7fFq88f8ArpC7kR1SBTe20Bt1AmpZDT2Dmfmlb/Q1UF'
    'jj/F3C77NCNQ344ZcAEI42HY+uighy5GdKQRHMoTT1OzyDG90ABjggQqDGW+zXzyIDAQAB",'
    '"keyMaterialType":"ASYMMETRIC_PUBLIC"'
    '},"status":"ENABLED","keyId":482168993,"outputPrefixType":"TINK"}]}')

RS256_JWK_SET_KID = (
    '{"keys":[{"kty":"RSA",'
    '"n":"AJLKZN-5Rgal5jz6tgi-SnQ3kce8RYk2naS943OJ12qn7QraTOqhMX63NiS2iLJ8KcHxj'
    'ApX3v2pSLNhq0_X6TPKA3gnHLwt_Q82YbEhZwBC4IIt4Z1jSkS30ldFCcwSPuYWeon1LL_FvJk'
    'hypbFTJrznwtj-fpe9qk8Dei3t4cugsRaebPacNNdQeydz1OubLcuhiPbHoQdgf5-534lsPWDe'
    'fvqX8MqIrc6DKFSjjqY-3xavPH_AK6Qu5EdUgU3ttAbdQJqWQ09g5n5pW_0NVBY4_xdwu-zQjU'
    'N-OGXABCONh2ProoIcuRnSkERzKE09Ts8gxvdAAY4IEKgxlvs188",'
    '"e":"AQAB","use":"sig","alg":"RS256","key_ops":["verify"],'
    '"kid":"HL1QoQ"}]}')

RS384_KEYSET = (
    '{"primaryKeyId":333504275,"key":[{"keyData":{'
    '"typeUrl":"type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey"'
    ',"value":"EAIagQMAnlBY5WD7gVQjNKvrS2whLKzt0Eql72B6haZ17eKifNn4S49eGdBy9RLj'
    '/mvHXAbacrngt9fzi0iv/WQ57jUmtO1b/wLt5LYk9APsBYjywDCIe+u9UouikP7c3SBqjjQijZ'
    '50jgYbMY6cL7s2Gx5lI1vlGX3ZExLVYbNoI9VBFAWjSDefd6GugESxXQFnnO3p2GHOKryZLeDH'
    '/KzVacTq2/pVXKVH/9/EQzcLB0oYUljZ4vYQ4HCAcwnUZbirsRwA0350Dz0Mlj+3+9sSAF8FPA'
    '+F/wlIBkPqjJ26b80V5FU4mBTzvYoXGTjkD7+bxH9p28huJSU96P4WdG5PYVwI1VEYwGipkUIp'
    'MWjJ7dXAtmltHzM9vkUt2bsBe9vyJjmRXyoC6mHSJbSyOm9Dd8BENobcUL9h+aBoxruY+mU49k'
    'AHzzeAntn8C+vIrxN+X6N2EU9N8t9BF+mwYiBEsY54wx99RbRrY9yICfPBmQJGwXSxNCXBRrbJ'
    'yxkIVuqvACP5IgMBAAE=",'
    '"keyMaterialType":"ASYMMETRIC_PUBLIC"'
    '},"status":"ENABLED","keyId":333504275,"outputPrefixType":"RAW"}]}')

RS384_JWK_SET = (
    '{"keys":[{"kty":"RSA",'
    '"n":"AJ5QWOVg-4FUIzSr60tsISys7dBKpe9geoWmde3ionzZ-EuPXhnQcvUS4_5rx1wG2nK54'
    'LfX84tIr_1kOe41JrTtW_8C7eS2JPQD7AWI8sAwiHvrvVKLopD-3N0gao40Io2edI4GGzGOnC-'
    '7NhseZSNb5Rl92RMS1WGzaCPVQRQFo0g3n3ehroBEsV0BZ5zt6dhhziq8mS3gx_ys1WnE6tv6V'
    'VylR__fxEM3CwdKGFJY2eL2EOBwgHMJ1GW4q7EcANN-dA89DJY_t_vbEgBfBTwPhf8JSAZD6oy'
    'dum_NFeRVOJgU872KFxk45A-_m8R_advIbiUlPej-FnRuT2FcCNVRGMBoqZFCKTFoye3VwLZpb'
    'R8zPb5FLdm7AXvb8iY5kV8qAuph0iW0sjpvQ3fARDaG3FC_YfmgaMa7mPplOPZAB883gJ7Z_Av'
    'ryK8Tfl-jdhFPTfLfQRfpsGIgRLGOeMMffUW0a2PciAnzwZkCRsF0sTQlwUa2ycsZCFbq'
    'rwAj-Q",'
    '"e":"AQAB","use":"sig","alg":"RS384","key_ops":["verify"]}]}')

RS512_KEYSET = (
    '{"primaryKeyId":705596479,"key":[{"keyData":{'
    '"typeUrl":"type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey"'
    ',"value":"EAMagQQAkKxZ9IRzF56gh47RXLJzQ6lffcnBmQSwvxUDJ0wHpKZzfAawOn1uidbg'
    'EoQ3XWOgtNvi7QeKLE4GjQa5bY0xdRnu8nKjFcsvH+eu1sV8oVoZ984J5mT1mhwU6nt26p4xKy'
    'eapMhzYYNvKudQjQJ8SbpVOFpEiJ7j0ECMUd4Q8mCUqWsrXYE8+1CcHjprsIxdot+haCARc72R'
    'Bj9cLuBIhJNzlFXNmsYh8yoSiEYr/auRvg/kIlNlnlOK/rJM/jMXbB6FuWdePrtqZ+ce2TVyAR'
    'qjZJ0G0vZcPuvOhgS4LM7/Aeal84ZhIcHladSo/g8pK1eUhnRqRXJpsltwux+1XVJeg2a0FQ0B'
    'N3Ft25uu5jhfvGWXeTkQOR7LbpbxKTI+vumSy9dmY4UrgAG37N8Xj5/NeqBT51L3qE6tk2ZLoO'
    '7yjRjhADK5lnbb4iYWWvWd3kqyv0JVlxfDzjAaYtiduEUIdCe45MGk8DpCn9Lnjlunhm4QyQuf'
    'K8k8UPiBbWNEODI8pjTSEjs0wyMqhegBKAvtVEhr029bg3Lv7YjN9FDvx4usuWGc16bXkTqNgC'
    'K4KzPG7PwV120r6IVGflfpSkd5rrkzDY01fsP0mW57QCHA67bxqLUECr2dAfNzz6ddS9pqXQyX'
    'ZWCyWKcvTFsGrr1oECwDOmW+nUIHGklr9Q0iAwEAAQ==",'
    '"keyMaterialType":"ASYMMETRIC_PUBLIC"'
    '},"status":"ENABLED","keyId":705596479,"outputPrefixType":"RAW"}]}')

RS512_JWK_SET = (
    '{"keys":[{"kty":"RSA",'
    '"n":"AJCsWfSEcxeeoIeO0Vyyc0OpX33JwZkEsL8VAydMB6Smc3wGsDp9bonW4BKEN11joLTb4'
    'u0HiixOBo0GuW2NMXUZ7vJyoxXLLx_nrtbFfKFaGffOCeZk9ZocFOp7duqeMSsnmqTIc2GDbyr'
    'nUI0CfEm6VThaRIie49BAjFHeEPJglKlrK12BPPtQnB46a7CMXaLfoWggEXO9kQY_XC7gSISTc'
    '5RVzZrGIfMqEohGK_2rkb4P5CJTZZ5Tiv6yTP4zF2wehblnXj67amfnHtk1cgEao2SdBtL2XD7'
    'rzoYEuCzO_wHmpfOGYSHB5WnUqP4PKStXlIZ0akVyabJbcLsftV1SXoNmtBUNATdxbdubruY4X'
    '7xll3k5EDkey26W8SkyPr7pksvXZmOFK4ABt-zfF4-fzXqgU-dS96hOrZNmS6Du8o0Y4QAyuZZ'
    '22-ImFlr1nd5Ksr9CVZcXw84wGmLYnbhFCHQnuOTBpPA6Qp_S545bp4ZuEMkLnyvJPFD4gW1jR'
    'DgyPKY00hI7NMMjKoXoASgL7VRIa9NvW4Ny7-2IzfRQ78eLrLlhnNem15E6jYAiuCszxuz8Fdd'
    'tK-iFRn5X6UpHea65Mw2NNX7D9Jlue0AhwOu28ai1BAq9nQHzc8-nXUvaal0Ml2VgslinL0xbB'
    'q69aBAsAzplvp1CBxpJa_UN",'
    '"e":"AQAB","use":"sig","alg":"RS512","key_ops":["verify"]}]}')

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

PS256_KEYSET = (
    '{"primaryKeyId":1508587714,"key":[{"keyData":{'
    '"typeUrl":"type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey",'
    '"value":"EAEagQMAj7Eud2n5G11qsdtjpgGWjW4cAKalSE1atm7d+Cp8biRX9wbmLJRMUvoO2'
    'j7Sp9Szx1TMmksY2Ugf/7+Nv9fY7vBbmxOiBQVTvikWn0FgPwhFTXTz+9fhGjM6E6sdSOUzjM6'
    'nsPulKqOQ8Aed+TLIlgvwuSTF4B5d6QkZWBymq7My6vV+epzWnoLpVDzCHh+c35r81Pyrj6tiT'
    'PQzPLN2ixeanclMjx8deNwlak3vwBdMDgwQ63rVCo2eWDS/BYK4rG22luSTDVfQVHU1NXlwXEn'
    'b/eONFSF6ZbD6JXFMT3uHT4okTOrX4Kd34stbPIUtZFUy3XiSeCGtghBXLMf/ge113Q9WDJ+RN'
    '1Xa4vgHJCO0+VO+cAugVkiu9UgsPP8o/r7tA2aP/Ps8EHYa1IaZg75vnrMZPvsTH7WG2SjSgW9'
    'GLLsbNJLFFqLFMwPuZPe8BbgvimPdStXasX/PN6DLKoK2PaT0I+iLK9mRi1Z4OjFbl9KAZXXEl'
    'hAQTzrEI2adIgMBAAE=",'
    '"keyMaterialType":"ASYMMETRIC_PUBLIC"'
    '},"status":"ENABLED","keyId":1508587714,"outputPrefixType":"RAW"}]}')


class JwkSetConverterTest(parameterized.TestCase):

  @parameterized.named_parameters([
      ('ES256_RAW', ES256_KEYSET, ES256_JWK_SET),
      ('ES384_RAW', ES384_KEYSET, ES384_JWK_SET),
      ('ES512_RAW', ES512_KEYSET, ES512_JWK_SET),
      ('WITH_DISABLED_KEY', KEYSET_WITH_DISABLED_KEY, ES256_JWK_SET),
      ('ES256_TINK', ES256_KEYSET_TINK, ES256_JWK_SET_KID),
      ('RS256_RAW', RS256_KEYSET, RS256_JWK_SET),
      ('RS384_RAW', RS384_KEYSET, RS384_JWK_SET),
      ('RS512_RAW', RS512_KEYSET, RS512_JWK_SET),
      ('RS256_TINK', RS256_KEYSET_TINK, RS256_JWK_SET_KID)
  ])
  def test_convert_from_jwt_key(self, tink_keyset, expected_jwk_set):
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

  @parameterized.named_parameters([
      ('ES256_RAW', ES256_KEYSET),
      ('RS256_RAW', RS256_KEYSET)
  ])
  def test_from_legacy_ecdsa_keyset_fails(self, keyset):
    legacy_keyset = keyset.replace('RAW', 'LEGACY')
    reader = tink.JsonKeysetReader(legacy_keyset)
    keyset_handle = cleartext_keyset_handle.read(reader)
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_from_keyset_handle(keyset_handle)

  @parameterized.named_parameters([
      ('ES256_RAW', ES256_KEYSET),
      ('RS256_RAW', RS256_KEYSET)
  ])
  def test_from_crunchy_ecdsa_keyset_fails(self, keyset):
    crunchy_keyset = keyset.replace('RAW', 'CRUNCHY')
    reader = tink.JsonKeysetReader(crunchy_keyset)
    keyset_handle = cleartext_keyset_handle.read(reader)
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_from_keyset_handle(keyset_handle)

  def test_from_ps256_keyset_fails(self):
    reader = tink.JsonKeysetReader(PS256_KEYSET)
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
