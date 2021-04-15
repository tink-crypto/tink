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

from tink import aead
from tink import daead
from tink import hybrid
from tink import mac
from tink import prf
from tink import signature
from tink import streaming_aead

from tink.proto import common_pb2
from tink.proto import tink_pb2
from tink import jwt

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


# Fake KMS keys are base64-encoded keysets. Each server must register a
# fake KmsClient that can handle these keys.
_FAKE_KMS_KEY_URI = (
    'fake-kms://CM2b3_MDElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRv'
    'LnRpbmsuQWVzR2NtS2V5EhIaEIK75t5L-adlUwVhWvRuWUwYARABGM2b3_MDIAE')


# All languages that are supported by a KeyType
SUPPORTED_LANGUAGES = {
    'AesEaxKey': ['cc', 'java', 'python'],
    'AesGcmKey': ['cc', 'java', 'go', 'python'],
    'AesGcmSivKey': ['cc', 'python'],
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
    'JwtEcdsaPrivateKey': ['cc', 'java'],
    'JwtRsaSsaPkcs1PrivateKey': ['cc', 'java'],
    'JwtRsaSsaPssPrivateKey': ['cc', 'java'],
}

KEY_TYPE_FROM_URL = {
    'type.googleapis.com/google.crypto.tink.' + key_type: key_type
    for key_type in ALL_KEY_TYPES}

# For each KeyType, a list of all KeyTemplate Names that must be supported.
KEY_TEMPLATE_NAMES = {
    'AesEaxKey': ['AES128_EAX', 'AES256_EAX'],
    'AesGcmKey': ['AES128_GCM', 'AES256_GCM'],
    'AesGcmSivKey': ['AES128_GCM_SIV', 'AES256_GCM_SIV'],
    'AesCtrHmacAeadKey': ['AES128_CTR_HMAC_SHA256', 'AES256_CTR_HMAC_SHA256'],
    'ChaCha20Poly1305Key': ['CHACHA20_POLY1305'],
    'XChaCha20Poly1305Key': ['XCHACHA20_POLY1305'],
    'KmsAeadKey': ['FAKE_KMS_AEAD'],
    'KmsEnvelopeAeadKey': ['FAKE_KMS_ENVELOPE_AEAD_WITH_AES128_GCM'],
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
        'ECIES_P256_HKDF_HMAC_SHA256_XCHACHA20_POLY1305',
        'ECIES_P256_HKDF_HMAC_SHA256_AES256_SIV'
    ],
    'AesCmacKey': ['AES_CMAC'],
    'HmacKey': [
        'HMAC_SHA256_128BITTAG', 'HMAC_SHA256_256BITTAG',
        'HMAC_SHA512_256BITTAG', 'HMAC_SHA512_512BITTAG'
    ],
    'EcdsaPrivateKey': [
        'ECDSA_P256', 'ECDSA_P384', 'ECDSA_P384_SHA384', 'ECDSA_P521',
        'ECDSA_P256_IEEE_P1363', 'ECDSA_P384_IEEE_P1363',
        'ECDSA_P384_SHA384_IEEE_P1363', 'ECDSA_P521_IEEE_P1363'
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
    'HmacPrfKey': ['HMAC_PRF_SHA256', 'HMAC_PRF_SHA512'],
    'HkdfPrfKey': ['HKDF_PRF_SHA256'],
    'JwtHmacKey': ['JWT_HS256', 'JWT_HS384', 'JWT_HS512'],
    'JwtEcdsaPrivateKey': ['JWT_ES256', 'JWT_ES384', 'JWT_ES512'],
    'JwtRsaSsaPkcs1PrivateKey': [
        'JWT_RS256_2048_F4', 'JWT_RS256_3072_F4', 'JWT_RS384_3072_F4',
        'JWT_RS512_4096_F4'
    ],
    'JwtRsaSsaPssPrivateKey': [
        'JWT_PS256_2048_F4', 'JWT_PS256_3072_F4', 'JWT_PS384_3072_F4',
        'JWT_PS512_4096_F4'
    ],
}

# KeyTemplate (as Protobuf) for each KeyTemplate name.
KEY_TEMPLATE = {
    'AES128_EAX':
        aead.aead_key_templates.AES128_EAX,
    'AES256_EAX':
        aead.aead_key_templates.AES256_EAX,
    'AES128_GCM':
        aead.aead_key_templates.AES128_GCM,
    'AES256_GCM':
        aead.aead_key_templates.AES256_GCM,
    'AES128_GCM_SIV':
        aead.aead_key_templates.AES128_GCM_SIV,
    'AES256_GCM_SIV':
        aead.aead_key_templates.AES256_GCM_SIV,
    'AES128_CTR_HMAC_SHA256':
        aead.aead_key_templates.AES128_CTR_HMAC_SHA256,
    'AES256_CTR_HMAC_SHA256':
        aead.aead_key_templates.AES256_CTR_HMAC_SHA256,
    'CHACHA20_POLY1305':
        tink_pb2.KeyTemplate(
            type_url=('type.googleapis.com/google.crypto.tink.' +
                      'ChaCha20Poly1305Key'),
            output_prefix_type=tink_pb2.TINK),
    'XCHACHA20_POLY1305':
        aead.aead_key_templates.XCHACHA20_POLY1305,
    'FAKE_KMS_AEAD':
        aead.aead_key_templates.create_kms_aead_key_template(_FAKE_KMS_KEY_URI),
    'FAKE_KMS_ENVELOPE_AEAD_WITH_AES128_GCM':
        aead.aead_key_templates.create_kms_envelope_aead_key_template(
            _FAKE_KMS_KEY_URI, aead.aead_key_templates.AES128_GCM),
    'AES256_SIV':
        daead.deterministic_aead_key_templates.AES256_SIV,
    'AES128_CTR_HMAC_SHA256_4KB':
        streaming_aead.streaming_aead_key_templates.AES128_CTR_HMAC_SHA256_4KB,
    'AES128_CTR_HMAC_SHA256_1MB':
        streaming_aead.streaming_aead_key_templates.AES128_CTR_HMAC_SHA256_1MB,
    'AES256_CTR_HMAC_SHA256_4KB':
        streaming_aead.streaming_aead_key_templates.AES256_CTR_HMAC_SHA256_4KB,
    'AES256_CTR_HMAC_SHA256_1MB':
        streaming_aead.streaming_aead_key_templates.AES256_CTR_HMAC_SHA256_1MB,
    'AES128_GCM_HKDF_4KB':
        streaming_aead.streaming_aead_key_templates.AES128_GCM_HKDF_4KB,
    'AES128_GCM_HKDF_1MB':
        streaming_aead.streaming_aead_key_templates.AES128_GCM_HKDF_1MB,
    'AES256_GCM_HKDF_4KB':
        streaming_aead.streaming_aead_key_templates.AES256_GCM_HKDF_4KB,
    'AES256_GCM_HKDF_1MB':
        streaming_aead.streaming_aead_key_templates.AES256_GCM_HKDF_1MB,
    'ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM':
        hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM,
    'ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM':
        hybrid.hybrid_key_templates
        .ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_GCM,
    'ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256':
        hybrid.hybrid_key_templates
        .ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256,
    'ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256':
        hybrid.hybrid_key_templates
        .ECIES_P256_COMPRESSED_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256,
    'ECIES_P256_HKDF_HMAC_SHA256_XCHACHA20_POLY1305':
        hybrid.hybrid_key_templates.create_ecies_aead_hkdf_key_template(
            curve_type=common_pb2.NIST_P256,
            ec_point_format=common_pb2.UNCOMPRESSED,
            hash_type=common_pb2.SHA256,
            dem_key_template=aead.aead_key_templates.XCHACHA20_POLY1305),
    'ECIES_P256_HKDF_HMAC_SHA256_AES256_SIV':
        hybrid.hybrid_key_templates.create_ecies_aead_hkdf_key_template(
            curve_type=common_pb2.NIST_P256,
            ec_point_format=common_pb2.COMPRESSED,
            hash_type=common_pb2.SHA256,
            dem_key_template=daead.deterministic_aead_key_templates.AES256_SIV),
    'AES_CMAC':
        mac.mac_key_templates.AES_CMAC,
    'HMAC_SHA256_128BITTAG':
        mac.mac_key_templates.HMAC_SHA256_128BITTAG,
    'HMAC_SHA256_256BITTAG':
        mac.mac_key_templates.HMAC_SHA256_256BITTAG,
    'HMAC_SHA512_256BITTAG':
        mac.mac_key_templates.HMAC_SHA512_256BITTAG,
    'HMAC_SHA512_512BITTAG':
        mac.mac_key_templates.HMAC_SHA512_512BITTAG,
    'ECDSA_P256':
        signature.signature_key_templates.ECDSA_P256,
    'ECDSA_P384':
        signature.signature_key_templates.ECDSA_P384,
    'ECDSA_P384_SHA384':
        signature.signature_key_templates.ECDSA_P384_SHA384,
    'ECDSA_P521':
        signature.signature_key_templates.ECDSA_P521,
    'ECDSA_P256_IEEE_P1363':
        signature.signature_key_templates.ECDSA_P256_IEEE_P1363,
    'ECDSA_P384_IEEE_P1363':
        signature.signature_key_templates.ECDSA_P384_IEEE_P1363,
    'ECDSA_P384_SHA384_IEEE_P1363':
        signature.signature_key_templates.ECDSA_P384_SHA384_IEEE_P1363,
    'ECDSA_P521_IEEE_P1363':
        signature.signature_key_templates.ECDSA_P521_IEEE_P1363,
    'ED25519':
        signature.signature_key_templates.ED25519,
    'RSA_SSA_PKCS1_3072_SHA256_F4':
        signature.signature_key_templates.RSA_SSA_PKCS1_3072_SHA256_F4,
    'RSA_SSA_PKCS1_4096_SHA512_F4':
        signature.signature_key_templates.RSA_SSA_PKCS1_4096_SHA512_F4,
    'RSA_SSA_PSS_3072_SHA256_SHA256_32_F4':
        signature.signature_key_templates.RSA_SSA_PSS_3072_SHA256_SHA256_32_F4,
    'RSA_SSA_PSS_4096_SHA512_SHA512_64_F4':
        signature.signature_key_templates.RSA_SSA_PSS_4096_SHA512_SHA512_64_F4,
    'AES_CMAC_PRF':
        prf.prf_key_templates.AES_CMAC,
    'HMAC_PRF_SHA256':
        prf.prf_key_templates.HMAC_SHA256,
    'HMAC_PRF_SHA512':
        prf.prf_key_templates.HMAC_SHA512,
    'HKDF_PRF_SHA256':
        prf.prf_key_templates.HKDF_SHA256,
    'JWT_HS256': jwt.jwt_hs256_template(),
    'JWT_HS384': jwt.jwt_hs384_template(),
    'JWT_HS512': jwt.jwt_hs512_template(),
    'JWT_ES256': jwt.jwt_es256_template(),
    'JWT_ES384': jwt.jwt_es384_template(),
    'JWT_ES512': jwt.jwt_es512_template(),
    'JWT_RS256_2048_F4': jwt.jwt_rs256_2048_f4_template(),
    'JWT_RS256_3072_F4': jwt.jwt_rs256_3072_f4_template(),
    'JWT_RS384_3072_F4': jwt.jwt_rs384_3072_f4_template(),
    'JWT_RS512_4096_F4': jwt.jwt_rs512_4096_f4_template(),
    'JWT_PS256_2048_F4': jwt.jwt_ps256_2048_f4_template(),
    'JWT_PS256_3072_F4': jwt.jwt_ps256_3072_f4_template(),
    'JWT_PS384_3072_F4': jwt.jwt_ps384_3072_f4_template(),
    'JWT_PS512_4096_F4': jwt.jwt_ps512_4096_f4_template(),
}


# Key template names for which the list of supported languages is different from
# the list of supported languages of the whole key type.
_CUSTOM_SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME = {
    'ECIES_P256_HKDF_HMAC_SHA256_XCHACHA20_POLY1305': ['cc', 'python'],
}


def _supported_languages_by_template(
    template_name: Text, template: tink_pb2.KeyTemplate) -> List[Text]:
  if template_name in _CUSTOM_SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME:
    return _CUSTOM_SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[template_name]
  return SUPPORTED_LANGUAGES[KEY_TYPE_FROM_URL[template.type_url]]


SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME = {
    name: _supported_languages_by_template(name, template)
    for name, template in KEY_TEMPLATE.items()
}
