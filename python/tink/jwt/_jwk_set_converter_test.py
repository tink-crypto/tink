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

from tink.proto import tink_pb2
import tink
from tink import jwt
from tink import secret_key_access

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

PS256_JWK_SET = (
    '{"keys":[{"kty":"RSA",'
    '"n":"AI-xLndp-RtdarHbY6YBlo1uHACmpUhNWrZu3fgqfG4kV_cG5iyUTFL6Dto-0qfUs8dUz'
    'JpLGNlIH_-_jb_X2O7wW5sTogUFU74pFp9BYD8IRU108_vX4RozOhOrHUjlM4zOp7D7pSqjkPA'
    'HnfkyyJYL8LkkxeAeXekJGVgcpquzMur1fnqc1p6C6VQ8wh4fnN-a_NT8q4-rYkz0MzyzdosXm'
    'p3JTI8fHXjcJWpN78AXTA4MEOt61QqNnlg0vwWCuKxttpbkkw1X0FR1NTV5cFxJ2_3jjRUhemW'
    'w-iVxTE97h0-KJEzq1-Cnd-LLWzyFLWRVMt14knghrYIQVyzH_4Htdd0PVgyfkTdV2uL4ByQjt'
    'PlTvnALoFZIrvVILDz_KP6-7QNmj_z7PBB2GtSGmYO-b56zGT77Ex-1htko0oFvRiy7GzSSxRa'
    'ixTMD7mT3vAW4L4pj3UrV2rF_zzegyyqCtj2k9CPoiyvZkYtWeDoxW5fSgGV1xJYQEE86xCNmn'
    'Q",'
    '"e":"AQAB","use":"sig","alg":"PS256","key_ops":["verify"]}]}')

PS256_KEYSET_TINK = (
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
    '},"status":"ENABLED","keyId":1508587714,"outputPrefixType":"TINK"}]}')

PS256_JWK_SET_KID = (
    '{"keys":[{"kty":"RSA",'
    '"n":"AI-xLndp-RtdarHbY6YBlo1uHACmpUhNWrZu3fgqfG4kV_cG5iyUTFL6Dto-0qfUs8dUz'
    'JpLGNlIH_-_jb_X2O7wW5sTogUFU74pFp9BYD8IRU108_vX4RozOhOrHUjlM4zOp7D7pSqjkPA'
    'HnfkyyJYL8LkkxeAeXekJGVgcpquzMur1fnqc1p6C6VQ8wh4fnN-a_NT8q4-rYkz0MzyzdosXm'
    'p3JTI8fHXjcJWpN78AXTA4MEOt61QqNnlg0vwWCuKxttpbkkw1X0FR1NTV5cFxJ2_3jjRUhemW'
    'w-iVxTE97h0-KJEzq1-Cnd-LLWzyFLWRVMt14knghrYIQVyzH_4Htdd0PVgyfkTdV2uL4ByQjt'
    'PlTvnALoFZIrvVILDz_KP6-7QNmj_z7PBB2GtSGmYO-b56zGT77Ex-1htko0oFvRiy7GzSSxRa'
    'ixTMD7mT3vAW4L4pj3UrV2rF_zzegyyqCtj2k9CPoiyvZkYtWeDoxW5fSgGV1xJYQEE86xCNmn'
    'Q",'
    '"e":"AQAB","use":"sig","alg":"PS256","key_ops":["verify"],'
    '"kid":"Wes4wg"}]}')

PS384_KEYSET = (
    '{"primaryKeyId":1042230435,"key":[{"keyData":{'
    '"typeUrl":"type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey",'
    '"value":"EAIagQMAv6a0OergWYmY1k6l6vx6Of5+RxCeeQ9jMTXQyvO0GCgMDExxtqVS8S25e'
    'hZ5LNDIiGjhE3v2++D7QEjnzOC5UqI1ZwPxUBSrOaf5oDbJ9vBc2c7wDyJhRV8UobQSpzunD4k'
    'XypVhytjwRdiP61vG0C/eL0x+LijtM/XVee1Y+5mWrypVrB6EHKtdkMx2WIYNpsFOForFrr6Jz'
    'LbWfDRWoqbCXKYivnw+CSE38ddW1XsrAT76E2Vf+womuwyBbkjLaiWvNxNFBTap2IaBLKAni6x'
    '7pqYCeu1n9eMUi41oz9QM8xfOvpH+wubc2PjwyTsb1FDTLnhV36tQLTVGdQdCDMF2Z8Agrnio3'
    'n1SFjSbYgFyVtpCwFKM2Z0zfO7k9jVbYYkzglzkJfp/lQrsuWqe4CVJjFE1H4BxcU7L0j8755k'
    'GJI08h1b7LPgqJcPgtHjcqbxHFU2yOf7mNGlW7YTnoQBO0StzQUk7kEw3X0+niEwX/L8j'
    'qW4YMbxrGdAfkTnPIgMBAAE=",'
    '"keyMaterialType":"ASYMMETRIC_PUBLIC"'
    '},"status":"ENABLED","keyId":1042230435,"outputPrefixType":"RAW"}]}')

PS384_JWK_SET = (
    '{"keys":[{"kty":"RSA",'
    '"n":"AL-mtDnq4FmJmNZOper8ejn-fkcQnnkPYzE10MrztBgoDAxMcbalUvEtuXoWeSzQyIho4'
    'RN79vvg-0BI58zguVKiNWcD8VAUqzmn-aA2yfbwXNnO8A8iYUVfFKG0Eqc7pw-JF8qVYcrY8EX'
    'Yj-tbxtAv3i9Mfi4o7TP11XntWPuZlq8qVawehByrXZDMdliGDabBThaKxa6-icy21nw0VqKmw'
    'lymIr58PgkhN_HXVtV7KwE--hNlX_sKJrsMgW5Iy2olrzcTRQU2qdiGgSygJ4use6amAnrtZ_X'
    'jFIuNaM_UDPMXzr6R_sLm3Nj48Mk7G9RQ0y54Vd-rUC01RnUHQgzBdmfAIK54qN59UhY0m2IBc'
    'lbaQsBSjNmdM3zu5PY1W2GJM4Jc5CX6f5UK7LlqnuAlSYxRNR-AcXFOy9I_O-eZBiSNPIdW-yz'
    '4KiXD4LR43Km8RxVNsjn-5jRpVu2E56EATtErc0FJO5BMN19Pp4hMF_y_I6luGDG8axnQH5E5z'
    'w",'
    '"e":"AQAB","use":"sig","alg":"PS384","key_ops":["verify"]}]}')

PS512_KEYSET = (
    '{"primaryKeyId":257081135,"key":[{"keyData":{'
    '"typeUrl":"type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey",'
    '"value":"EAMagQQAnOUQvBwNRgeI3zlzIhVo4NzFVCsQn9hd2EIclz6cWBRMFr4EX5lXLK0St'
    'SIB7EQP4ciHa+vr59sOgMFMC2kiXRUXNtl99QhGwH0YjbWeDC50PKEAjH1hhhPgSw2dFcUVs4j'
    'bScDrwNn1sQ8rkgSNczvQNpV1MtBhS/CC1PxVF88JaejG2zr+unoFlw7xnqxBWMzNrMHZHwqga'
    '2vL3inSbvA/RGQjnE2DzQSwZkXthGSwYBjOYbGawMN4onkAx/myHMyTg/TLAqG9GUyB0DVelvV'
    'oGZG/QJBY2Fp2FlpOQRKeBr6pC7Lk8zZL4GJk264KoOpG8v1t7PveN+STIdTE2D548K+GDOvsv'
    'rO4ZhofS/iqN9xLucuU1HkqKUqyLvMxsWum8Zhp7zinFdBnDOgeheOHUgN/iwjupk6u1Svt+RW'
    'NJsfb2l0jrvzf0cRMbPeLZRmpDwBxBvXWo61u6uaBEVb+ooZ6K5+hx3Rld7wXktjYIZzHqUr39'
    'P5yTw28b8Y2dPFWR4vwr2/0zBxcDmTRRtQ7vPOtZPD0/LVIXkgbBiLILpycnucWt9Lq9Hc62KF'
    'iTQOAuuOxz7ObBegXjnFupiZZ9PyzO5WgT9lRpH7U7tzGLAjV+AUpjH6HA1o6bRLKOHFBPS+I9'
    'IqAYb/RpF6M/6hCmC2Rz64yYzR3y4vHKGMiAwEAAQ==",'
    '"keyMaterialType":"ASYMMETRIC_PUBLIC"'
    '},"status":"ENABLED","keyId":257081135,"outputPrefixType":"RAW"}]}')

PS512_JWK_SET = (
    '{"keys":[{"kty":"RSA",'
    '"n":"AJzlELwcDUYHiN85cyIVaODcxVQrEJ_YXdhCHJc-nFgUTBa-BF-ZVyytErUiAexED-HIh'
    '2vr6-fbDoDBTAtpIl0VFzbZffUIRsB9GI21ngwudDyhAIx9YYYT4EsNnRXFFbOI20nA68DZ9bE'
    'PK5IEjXM70DaVdTLQYUvwgtT8VRfPCWnoxts6_rp6BZcO8Z6sQVjMzazB2R8KoGtry94p0m7wP'
    '0RkI5xNg80EsGZF7YRksGAYzmGxmsDDeKJ5AMf5shzMk4P0ywKhvRlMgdA1Xpb1aBmRv0CQWNh'
    'adhZaTkESnga-qQuy5PM2S-BiZNuuCqDqRvL9bez73jfkkyHUxNg-ePCvhgzr7L6zuGYaH0v4q'
    'jfcS7nLlNR5KilKsi7zMbFrpvGYae84pxXQZwzoHoXjh1IDf4sI7qZOrtUr7fkVjSbH29pdI67'
    '839HETGz3i2UZqQ8AcQb11qOtburmgRFW_qKGeiufocd0ZXe8F5LY2CGcx6lK9_T-ck8NvG_GN'
    'nTxVkeL8K9v9MwcXA5k0UbUO7zzrWTw9Py1SF5IGwYiyC6cnJ7nFrfS6vR3OtihYk0DgLrjsc-'
    'zmwXoF45xbqYmWfT8szuVoE_ZUaR-1O7cxiwI1fgFKYx-hwNaOm0SyjhxQT0viPSKgGG_0aRej'
    'P-oQpgtkc-uMmM0d8uLxyhj",'
    '"e":"AQAB","use":"sig","alg":"PS512","key_ops":["verify"]}]}')

HS256_KEYSET = """
    {
      "primaryKeyId": 872908418,
      "key": [
        {
          "keyData": {
            "typeUrl": "type.googleapis.com/google.crypto.tink.JwtHmacKey",
            "value": "GiA2qUishZ7cDwH/j2a9xcqqusSg1jKRnPux6XRxc5rvdRAB",
            "keyMaterialType": "SYMMETRIC"
          },
          "status": "ENABLED",
          "keyId": 872908418,
          "outputPrefixType": "TINK"
        }
      ]
    }"""

KEYSET_WITH_TWO_KEYS = (
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
    ',"value":"EAEagQIAkspk37lGBqXmPPq2CL5KdDeRx7xFiTadpL3jc4nXaqftCtpM6qExfrc2'
    'JLaIsnwpwfGMClfe/alIs2GrT9fpM8oDeCccvC39DzZhsSFnAELggi3hnWNKRLfSV0UJzBI+5h'
    'Z6ifUsv8W8mSHKlsVMmvOfC2P5+l72qTwN6Le3hy6CxFp5s9pw011B7J3PU65sty6GI9sehB2B'
    '/n7nfiWw9YN5++pfwyoitzoMoVKOOpj7fFq88f8ArpC7kR1SBTe20Bt1AmpZDT2Dmfmlb/Q1UF'
    'jj/F3C77NCNQ344ZcAEI42HY+uighy5GdKQRHMoTT1OzyDG90ABjggQqDGW+zXzyIDAQAB",'
    '"keyMaterialType":"ASYMMETRIC_PUBLIC"'
    '},"status":"ENABLED","keyId":482168993,"outputPrefixType":"RAW"}]}')

JWK_SET_WITH_TWO_KEYS = (
    '{"keys":[{'
    '"kty":"EC",'
    '"crv":"P-256",'
    '"x":"EM8jrqGMse-PGZQnafIcgEOZ061DiA-y9aBhiBnSDKA",'
    '"y":"UxCtK0wAqQG_e5vpr7SSgJNKt5h4z3FGZtAuBLng1uE",'
    '"use":"sig","alg":"ES256","key_ops":["verify"]},'
    '{"kty":"RSA",'
    '"n":"AJLKZN-5Rgal5jz6tgi-SnQ3kce8RYk2naS943OJ12qn7QraTOqhMX63NiS2iLJ8KcHxj'
    'ApX3v2pSLNhq0_X6TPKA3gnHLwt_Q82YbEhZwBC4IIt4Z1jSkS30ldFCcwSPuYWeon1LL_FvJk'
    'hypbFTJrznwtj-fpe9qk8Dei3t4cugsRaebPacNNdQeydz1OubLcuhiPbHoQdgf5-534lsPWDe'
    'fvqX8MqIrc6DKFSjjqY-3xavPH_AK6Qu5EdUgU3ttAbdQJqWQ09g5n5pW_0NVBY4_xdwu-zQjU'
    'N-OGXABCONh2ProoIcuRnSkERzKE09Ts8gxvdAAY4IEKgxlvs188",'
    '"e":"AQAB","use":"sig","alg":"RS256","key_ops":["verify"]}]}')


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
      ('RS256_TINK', RS256_KEYSET_TINK, RS256_JWK_SET_KID),
      ('PS256_RAW', PS256_KEYSET, PS256_JWK_SET),
      ('PS384_RAW', PS384_KEYSET, PS384_JWK_SET),
      ('PS512_RAW', PS512_KEYSET, PS512_JWK_SET),
      ('PS256_TINK', PS256_KEYSET_TINK, PS256_JWK_SET_KID),
      ('TWO_KEYS', KEYSET_WITH_TWO_KEYS, JWK_SET_WITH_TWO_KEYS)
  ])
  def test_convert_from_jwt_key(self, tink_keyset, expected_jwk_set):
    keyset_handle = tink.json_proto_keyset_format.parse_without_secret(
        tink_keyset
    )
    jwk_set = jwt.jwk_set_from_public_keyset_handle(keyset_handle)
    self.assertEqual(jwk_set, expected_jwk_set)

  @parameterized.named_parameters([('ES256_RAW', ES256_JWK_SET),
                                   ('ES384_RAW', ES384_JWK_SET),
                                   ('ES512_RAW', ES512_JWK_SET),
                                   ('ES256_TINK', ES256_JWK_SET_KID),
                                   ('RS256_RAW', RS256_JWK_SET),
                                   ('RS384_RAW', RS384_JWK_SET),
                                   ('RS512_RAW', RS512_JWK_SET),
                                   ('RS256_TINK', RS256_JWK_SET_KID),
                                   ('PS256_RAW', RS256_JWK_SET),
                                   ('PS384_RAW', RS384_JWK_SET),
                                   ('PS512_RAW', RS512_JWK_SET),
                                   ('PS256_TINK', RS256_JWK_SET_KID)])
  def test_convert_jwk_set_to_public_keyset_handle_and_back(self, jwk_set):
    keyset_handle = jwt.jwk_set_to_public_keyset_handle(jwk_set)
    output_jwk_set = jwt.jwk_set_from_public_keyset_handle(keyset_handle)
    self.assertEqual(output_jwk_set, jwk_set)
    # check that all keys are raw.
    for key in keyset_handle._keyset.key:
      self.assertEqual(key.output_prefix_type, tink_pb2.RAW)

    # test deprecated to/from keyset_handle functions.
    self.assertEqual(
        jwt.jwk_set_from_keyset_handle(jwt.jwk_set_to_keyset_handle(jwk_set)),
        jwk_set)

  def test_es_conserves_empty_kid(self):
    jwk_set_with_empty_kid = ES256_JWK_SET_KID.replace('"ENgjPA"', '""')
    keyset_handle = jwt.jwk_set_to_public_keyset_handle(jwk_set_with_empty_kid)
    output_jwk_set = jwt.jwk_set_from_public_keyset_handle(keyset_handle)
    self.assertEqual(output_jwk_set, jwk_set_with_empty_kid)

  def test_primary_key_id_missing_success(self):
    keyset = ES256_KEYSET.replace('"primaryKeyId":282600252,', '')
    keyset_handle = tink.json_proto_keyset_format.parse_without_secret(keyset)
    jwk_set = jwt.jwk_set_from_public_keyset_handle(keyset_handle)
    self.assertEqual(jwk_set, ES256_JWK_SET)

  @parameterized.named_parameters([
      ('ES256_RAW', ES256_KEYSET),
      ('RS256_RAW', RS256_KEYSET),
      ('PS256_RAW', PS256_KEYSET)
  ])
  def test_from_legacy_ecdsa_keyset_fails(self, keyset):
    legacy_keyset = keyset.replace('RAW', 'LEGACY')
    keyset_handle = tink.json_proto_keyset_format.parse_without_secret(
        legacy_keyset
    )
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_from_public_keyset_handle(keyset_handle)

  @parameterized.named_parameters([
      ('ES256_RAW', ES256_KEYSET),
      ('RS256_RAW', RS256_KEYSET),
      ('PS256_RAW', RS256_KEYSET)
  ])
  def test_from_crunchy_ecdsa_keyset_fails(self, keyset):
    crunchy_keyset = keyset.replace('RAW', 'CRUNCHY')
    keyset_handle = tink.json_proto_keyset_format.parse_without_secret(
        crunchy_keyset
    )
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_from_public_keyset_handle(keyset_handle)

  def test_from_hs256_keyset_fails(self):
    keyset_handle = tink.json_proto_keyset_format.parse(
        HS256_KEYSET, secret_key_access.TOKEN
    )
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_from_public_keyset_handle(keyset_handle)

  def test_from_private_keyset_fails(self):
    keyset_handle = tink.json_proto_keyset_format.parse(
        PRIVATEKEY_KEYSET, secret_key_access.TOKEN
    )
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_from_public_keyset_handle(keyset_handle)

  def test_ecdsa_without_use_or_key_ops_to_public_keyset_handle_success(self):
    jwk_set = """{"keys":[
        {
           "kty":"EC",
           "crv":"P-256",
           "x":"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY",
           "y":"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI",
           "alg":"ES256"
        }]}"""
    # ignore returned value, we only test that it worked.
    jwt.jwk_set_to_public_keyset_handle(jwk_set)

  def test_ecdsa_private_key_to_public_keyset_handle_fails(self):
    # Example from https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.2
    jwk_set = """{"keys":[
        {
           "kty":"EC",
           "crv":"P-256",
           "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
           "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
           "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
           "alg":"ES256"
        }]}"""
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_to_public_keyset_handle(jwk_set)

  def test_ecdsa_key_with_unknown_field_to_public_keyset_handle_success(self):
    jwk_set = """{"keys":[
        {
           "kty":"EC",
           "crv":"P-256",
           "x":"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY",
           "y":"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI",
           "alg":"ES256",
           "unknown":1234,
           "use":"sig",
           "key_ops":["verify"]
        }]}"""
    jwt.jwk_set_to_public_keyset_handle(jwk_set)

  def test_ecdsa_key_without_alg_to_public_keyset_handle_fails(self):
    jwk_set = """{"keys":[
        {
           "kty":"EC",
           "crv":"P-256",
           "x":"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY",
           "y":"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI",
           "use":"sig",
           "key_ops":["verify"]
        }]}"""
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_to_public_keyset_handle(jwk_set)

  def test_ecdsa_key_without_kty_to_public_keyset_handle_fails(self):
    jwk_set = """{"keys":[
        {
           "crv":"P-256",
           "x":"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY",
           "y":"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI",
           "alg":"ES256",
           "use":"sig",
           "key_ops":["verify"]
        }]}"""
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_to_public_keyset_handle(jwk_set)

  def test_ecdsa_key_without_crv_to_public_keyset_handle_fails(self):
    jwk_set = """{"keys":[
        {
           "kty":"EC",
           "x":"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY",
           "y":"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI",
           "alg":"ES256",
           "use":"sig",
           "key_ops":["verify"]
        }]}"""
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_to_public_keyset_handle(jwk_set)

  def test_ecdsa_key_with_small_x_primitive_fails(self):
    jwk_set = """{"keys":[
        {
           "kty":"EC",
           "crv":"P-256",
           "x":"AAAwOQ",
           "y":"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI",
           "alg":"ES256",
           "use":"sig",
           "key_ops":["verify"]
        }]}"""
    handle = jwt.jwk_set_to_public_keyset_handle(jwk_set)
    with self.assertRaises(tink.TinkError):
      handle.primitive(jwt.JwtPublicKeyVerify)

  def test_ecdsa_key_with_small_y_primitive_fails(self):
    jwk_set = """{"keys":[
        {
           "kty":"EC",
           "crv":"P-256",
           "x":"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY",
           "y":"AAAwOQ",
           "alg":"ES256",
           "use":"sig",
           "key_ops":["verify"]
        }]}"""
    handle = jwt.jwk_set_to_public_keyset_handle(jwk_set)
    with self.assertRaises(tink.TinkError):
      handle.primitive(jwt.JwtPublicKeyVerify)

  def test_ecdsa_key_with_invalid_kty_to_public_keyset_handle_fails(self):
    jwk_set = """{"keys":[
        {
           "kty":"RSA",
           "crv":"P-256",
           "x":"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY",
           "y":"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI",
           "alg":"ES256",
           "use":"sig",
           "key_ops":["verify"]
        }]}"""
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_to_public_keyset_handle(jwk_set)

  def test_ecdsa_key_with_invalid_crv_to_public_keyset_handle_fails(self):
    jwk_set = """{"keys":[
        {
           "kty":"EC",
           "crv":"P-384",
           "x":"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY",
           "y":"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI",
           "alg":"ES256",
           "use":"sig",
           "key_ops":["verify"]
        }]}"""
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_to_public_keyset_handle(jwk_set)

  def test_ecdsa_key_with_invalid_use_to_public_keyset_handle_fails(self):
    jwk_set = """{"keys":[
        {
           "kty":"EC",
           "crv":"P-256",
           "x":"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY",
           "y":"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI",
           "alg":"ES256",
           "use":"invalid",
           "key_ops":["verify"]
        }]}"""
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_to_public_keyset_handle(jwk_set)

  def test_ecdsa_key_with_invalid_key_ops_to_public_keyset_handle_fails(self):
    jwk_set = """{"keys":[
        {
           "kty":"EC",
           "crv":"P-256",
           "x":"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY",
           "y":"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI",
           "alg":"ES256",
           "use":"sig",
           "key_ops":["invalid"]
        }]}"""
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_to_public_keyset_handle(jwk_set)

  def test_ecdsa_key_with_string_key_ops_to_public_keyset_handle_fails(self):
    jwk_set = """{"keys":[
        {
           "kty":"EC",
           "crv":"P-256",
           "x":"KUPydf4k4cS5EGS82npjEUxKIiBfUGP3wlN49A2GxTY",
           "y":"b22m_Y4sT-jUJSxBVqjrW_DxWyBLopxYHTuFVfx70ZI",
           "alg":"ES256",
           "use":"sig",
           "key_ops":"verify"
        }]}"""
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_to_public_keyset_handle(jwk_set)

  def test_rsa_ssa_pkcs1_without_use_and_key_ops_to_keyset_handle_success(self):
    jwk_set = RS256_JWK_SET.replace(',"use":"sig"',
                                    '').replace(',"key_ops":["verify"]', '')
    keyset_handle = jwt.jwk_set_to_public_keyset_handle(jwk_set)
    output_jwk_set = jwt.jwk_set_from_public_keyset_handle(keyset_handle)
    self.assertEqual(output_jwk_set, RS256_JWK_SET)

  def test_rsa_ssa_pss_without_use_and_key_ops_to_keyset_handle_success(self):
    jwk_set = PS256_JWK_SET.replace(',"use":"sig"',
                                    '').replace(',"key_ops":["verify"]', '')
    keyset_handle = jwt.jwk_set_to_public_keyset_handle(jwk_set)
    output_jwk_set = jwt.jwk_set_from_public_keyset_handle(keyset_handle)
    self.assertEqual(output_jwk_set, PS256_JWK_SET)

  def test_rsa_ssa_pkcs1_with_unknown_property_keyset_handle_success(self):
    jwk_set = RS256_JWK_SET.replace(',"use":"sig"',
                                    ',"use":"sig","unknown":1234')
    keyset_handle = jwt.jwk_set_to_public_keyset_handle(jwk_set)
    output_jwk_set = jwt.jwk_set_from_public_keyset_handle(keyset_handle)
    self.assertEqual(output_jwk_set, RS256_JWK_SET)

  def test_rsa_ssa_pss_with_unknown_property_keyset_handle_success(self):
    jwk_set = PS256_JWK_SET.replace(',"use":"sig"',
                                    ',"use":"sig","unknown":1234')
    keyset_handle = jwt.jwk_set_to_public_keyset_handle(jwk_set)
    output_jwk_set = jwt.jwk_set_from_public_keyset_handle(keyset_handle)
    self.assertEqual(output_jwk_set, PS256_JWK_SET)

  def test_rsa_private_key_to_public_keyset_handle_fails(self):
    # Example from https://datatracker.ietf.org/doc/html/rfc7517#appendix-A.2
    jwk_set = """
     {"keys":
       [
         {"kty":"RSA",
          "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4
     cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMst
     n64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2Q
     vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS
     D08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw
     0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
          "e":"AQAB",
          "d":"X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9
     M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij
     wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d
     _cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz
     nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz
     me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
          "p":"83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV
     nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV
     WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
          "q":"3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum
     qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx
     kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
          "dp":"G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim
     YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu
     YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
          "dq":"s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU
     vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9
     GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
          "qi":"GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg
     UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx
     yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
          "alg":"RS256",
          "kid":"2011-04-29"}
       ]
     }"""
    # remove spaces and line breaks
    jwk_set = jwk_set.replace(' ', '').replace('\n', '')
    # PKCS1
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_to_public_keyset_handle(jwk_set)
    # PSS
    jwk_set = jwk_set.replace('"alg":"RS256"', '"alg":"PS256"')
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_to_public_keyset_handle(jwk_set)

  def test_rsa_without_alg_fails(self):
    jwk_set = RS256_JWK_SET.replace(',"alg":"RS256"', '')
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_to_public_keyset_handle(jwk_set)

  def test_rsa_without_kty_fails(self):
    jwk_set = RS256_JWK_SET.replace('"kty":"RSA",', '')
    # PKCS1
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_to_public_keyset_handle(jwk_set)
    # PSS
    jwk_set = jwk_set.replace('"alg":"RS256"', '"alg":"PS256"')
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_to_public_keyset_handle(jwk_set)

  def test_rsa_with_small_n_primitive_fails(self):
    jwk_set = """{"keys":[{
        "kty":"RSA",
        "n":"AAAwOQ",
        "e":"AQAB",
        "use":"sig",
        "alg":"RS256",
        "key_ops":["verify"]}]}"""
    # PKCS1
    handle = jwt.jwk_set_to_public_keyset_handle(jwk_set)
    with self.assertRaises(tink.TinkError):
      handle.primitive(jwt.JwtPublicKeyVerify)
    # test PSS
    jwk_set = jwk_set.replace('"alg":"RS256"', '"alg":"PS256"')
    handle = jwt.jwk_set_to_public_keyset_handle(jwk_set)
    with self.assertRaises(tink.TinkError):
      handle.primitive(jwt.JwtPublicKeyVerify)

  def test_rsa_with_invalid_kty_fails(self):
    jwk_set = RS256_JWK_SET.replace('"kty":"RSA"', '"kty":"EC"')
    # PKCS1
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_to_public_keyset_handle(jwk_set)
    # PSS
    jwk_set = jwk_set.replace('"alg":"RS256"', '"alg":"PS256"')
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_to_public_keyset_handle(jwk_set)

  def test_rsa_with_invalid_use_fails(self):
    jwk_set = RS256_JWK_SET.replace('"use":"sig"', '"use":"invalid"')
    # PKCS1
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_to_public_keyset_handle(jwk_set)
    # PSS
    jwk_set = jwk_set.replace('"alg":"RS256"', '"alg":"PS256"')
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_to_public_keyset_handle(jwk_set)

  def test_rsa_with_invalid_key_ops_fails(self):
    jwk_set = RS256_JWK_SET.replace('"key_ops":["verify"]',
                                    '"key_ops":["invalid"]')
    # PKCS1
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_to_public_keyset_handle(jwk_set)
    # PSS
    jwk_set = jwk_set.replace('"alg":"RS256"', '"alg":"PS256"')
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_to_public_keyset_handle(jwk_set)

  def test_rsa_with_string_key_ops_fails(self):
    jwk_set = RS256_JWK_SET.replace('"key_ops":["verify"]',
                                    '"key_ops":"verify"')
    # PKCS1
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_to_public_keyset_handle(jwk_set)
    # PSS
    jwk_set = jwk_set.replace('"alg":"RS256"', '"alg":"PS256"')
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_to_public_keyset_handle(jwk_set)

  def test_jwk_set_to_public_keyset_handle_with_invalid_json_raises_tink_error(
      self):
    with self.assertRaises(tink.TinkError):
      jwt.jwk_set_to_public_keyset_handle('invalid')

if __name__ == '__main__':
  absltest.main()
