# Copyright 2020 Google LLC
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
"""All KeyTypes and which languages support them."""

# Placeholder for import for type annotations

from typing import List, Text

# All languages supported by cross-language tests.
ALL_LANGUAGES = ['cc', 'java', 'go', 'python']

# All KeyTypes (without the prefix 'type.googleapis.com/google.crypto.tink.')
AEAD_KEY_TYPES = [
    'AesEaxKey',
    'AesGcmKey',
    'AesGcmSivKey',
    'AesCtrHmacAeadKey',
    'ChaCha20Poly1305Key',
    'XChaCha20Poly1305Key',
    'KmsAeadKey',
    'KmsEnvelopeAeadKey',
]
DAEAD_KEY_TYPES = ['AesSivKey']
STREAMING_AEAD_KEY_TYPES = [
    'AesCtrHmacStreamingKey',
    'AesGcmHkdfStreamingKey',
]
HYBRID_PRIVATE_KEY_TYPES = ['EciesAeadHkdfPrivateKey']
MAC_KEY_TYPES = [
    'AesCmacKey',
    'HmacKey',
]
SIGNATURE_KEY_TYPES = [
    'EcdsaPrivateKey',
    'Ed25519PrivateKey',
    'RsaSsaPkcs1PrivateKey',
    'RsaSsaPssPrivateKey',
]
PRF_KEY_TYPES = [
    'AesCmacPrfKey',
    'HmacPrfKey',
    'HkdfPrfKey',
]
JWT_MAC_KEY_TYPES = [
    'JwtHmacKey',
]
JWT_SIGNATURE_KEY_TYPES = [
    'JwtEcdsaPrivateKey',
    'JwtRsaSsaPkcs1PrivateKey',
    'JwtRsaSsaPssPrivateKey',
]

ALL_KEY_TYPES = (
    AEAD_KEY_TYPES + DAEAD_KEY_TYPES + STREAMING_AEAD_KEY_TYPES +
    HYBRID_PRIVATE_KEY_TYPES + MAC_KEY_TYPES + SIGNATURE_KEY_TYPES +
    PRF_KEY_TYPES + JWT_MAC_KEY_TYPES + JWT_SIGNATURE_KEY_TYPES)


# All languages that are supported by a KeyType
SUPPORTED_LANGUAGES = {
    'AesEaxKey': ['cc', 'java', 'python'],
    'AesGcmKey': ['cc', 'java', 'go', 'python'],
    'AesGcmSivKey': ['cc', 'go', 'python'],
    'AesCtrHmacAeadKey': ['cc', 'java', 'go', 'python'],
    'ChaCha20Poly1305Key': ['java', 'go'],
    'XChaCha20Poly1305Key': ['cc', 'java', 'go', 'python'],
    'KmsAeadKey': ['cc', 'java', 'python'],
    'KmsEnvelopeAeadKey': ['cc', 'java', 'go', 'python'],
    'AesSivKey': ['cc', 'java', 'go', 'python'],
    'AesCtrHmacStreamingKey': ['cc', 'java', 'go', 'python'],
    'AesGcmHkdfStreamingKey': ['cc', 'java', 'go', 'python'],
    'EciesAeadHkdfPrivateKey': ['cc', 'java', 'go', 'python'],
    'AesCmacKey': ['cc', 'java', 'go', 'python'],
    'HmacKey': ['cc', 'java', 'go', 'python'],
    'EcdsaPrivateKey': ['cc', 'java', 'go', 'python'],
    'Ed25519PrivateKey': ['cc', 'java', 'go', 'python'],
    'RsaSsaPkcs1PrivateKey': ['cc', 'java', 'python'],
    'RsaSsaPssPrivateKey': ['cc', 'java', 'python'],
    'AesCmacPrfKey': ['cc', 'java', 'go', 'python'],
    'HmacPrfKey': ['cc', 'java', 'go', 'python'],
    'HkdfPrfKey': ['cc', 'java', 'go', 'python'],
    'JwtHmacKey': ['cc', 'java', 'python'],
    'JwtEcdsaPrivateKey': ['cc', 'java', 'python'],
    'JwtRsaSsaPkcs1PrivateKey': ['cc', 'java', 'python'],
    'JwtRsaSsaPssPrivateKey': ['cc', 'java', 'python'],
}

KEY_TYPE_FROM_URL = {
    'type.googleapis.com/google.crypto.tink.' + key_type: key_type
    for key_type in ALL_KEY_TYPES}

# For each KeyType, a list of Tinkey KeyTemplate names.
# TODO(juerg): Add missing key template names, and remove deprecated names.
KEY_TEMPLATE_NAMES = {
    'AesEaxKey': ['AES128_EAX', 'AES256_EAX'],
    'AesGcmKey': ['AES128_GCM', 'AES256_GCM'],
    'AesGcmSivKey': ['AES128_GCM_SIV', 'AES256_GCM_SIV'],
    'AesCtrHmacAeadKey': ['AES128_CTR_HMAC_SHA256', 'AES256_CTR_HMAC_SHA256'],
    'ChaCha20Poly1305Key': ['CHACHA20_POLY1305'],
    'XChaCha20Poly1305Key': ['XCHACHA20_POLY1305'],
    'KmsAeadKey': [],
    'KmsEnvelopeAeadKey': [],
    'AesSivKey': ['AES256_SIV'],
    'AesCtrHmacStreamingKey': [
        'AES128_CTR_HMAC_SHA256_4KB',
        'AES128_CTR_HMAC_SHA256_1MB',
        'AES256_CTR_HMAC_SHA256_4KB',
        'AES256_CTR_HMAC_SHA256_1MB',
    ],
    'AesGcmHkdfStreamingKey': [
        'AES128_GCM_HKDF_4KB',
        'AES128_GCM_HKDF_1MB',
        'AES256_GCM_HKDF_4KB',
        'AES256_GCM_HKDF_1MB',
    ],
    'EciesAeadHkdfPrivateKey': [
        'ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM',
        'ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM',
        'ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256',
        'ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256',
    ],
    'AesCmacKey': ['AES_CMAC'],
    'HmacKey': [
        'HMAC_SHA256_128BITTAG', 'HMAC_SHA256_256BITTAG',
        'HMAC_SHA512_256BITTAG', 'HMAC_SHA512_512BITTAG'
    ],
    'EcdsaPrivateKey': [
        'ECDSA_P256', 'ECDSA_P384', 'ECDSA_P521',
        'ECDSA_P256_IEEE_P1363', 'ECDSA_P384_IEEE_P1363',
        'ECDSA_P521_IEEE_P1363'
    ],
    'Ed25519PrivateKey': ['ED25519'],
    'RsaSsaPkcs1PrivateKey': [
        'RSA_SSA_PKCS1_3072_SHA256_F4', 'RSA_SSA_PKCS1_4096_SHA512_F4'
    ],
    'RsaSsaPssPrivateKey': [
        'RSA_SSA_PSS_3072_SHA256_SHA256_32_F4',
        'RSA_SSA_PSS_4096_SHA512_SHA512_64_F4'
    ],
    'AesCmacPrfKey': ['AES_CMAC_PRF'],
    'HmacPrfKey': ['HMAC_SHA256_PRF', 'HMAC_SHA512_PRF'],
    'HkdfPrfKey': ['HKDF_SHA256'],
    'JwtHmacKey': [
        'JWT_HS256', 'JWT_HS256_RAW', 'JWT_HS384', 'JWT_HS384_RAW', 'JWT_HS512',
        'JWT_HS512_RAW'
    ],
    'JwtEcdsaPrivateKey': [
        'JWT_ES256', 'JWT_ES256_RAW', 'JWT_ES384', 'JWT_ES384_RAW', 'JWT_ES512',
        'JWT_ES512_RAW'
    ],
    'JwtRsaSsaPkcs1PrivateKey': [
        'JWT_RS256_2048_F4', 'JWT_RS256_2048_F4_RAW', 'JWT_RS256_3072_F4',
        'JWT_RS256_3072_F4_RAW', 'JWT_RS384_3072_F4', 'JWT_RS384_3072_F4_RAW',
        'JWT_RS512_4096_F4', 'JWT_RS512_4096_F4_RAW'
    ],
    'JwtRsaSsaPssPrivateKey': [
        'JWT_PS256_2048_F4', 'JWT_PS256_2048_F4_RAW', 'JWT_PS256_3072_F4',
        'JWT_PS256_3072_F4_RAW', 'JWT_PS384_3072_F4', 'JWT_PS384_3072_F4_RAW',
        'JWT_PS512_4096_F4', 'JWT_PS512_4096_F4_RAW'
    ],
}

# Key template names for which the list of supported languages is different from
# the list of supported languages of the whole key type.
_CUSTOM_SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME = {
    # currently empty.
}


def _supported_languages_by_template(
    template_name: Text, key_type: Text) -> List[Text]:
  if template_name in _CUSTOM_SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME:
    return _CUSTOM_SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[template_name]
  return SUPPORTED_LANGUAGES[key_type]


def _all_key_template_names_with_key_type():
  for key_type, template_names in KEY_TEMPLATE_NAMES.items():
    for template_name in template_names:
      yield (template_name, key_type)


SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME = {
    name: _supported_languages_by_template(name, template)
    for name, template in _all_key_template_names_with_key_type()
}
