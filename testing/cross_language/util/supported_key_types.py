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

from typing import Iterable, List, Text, Tuple

from tink import aead
from tink import daead
from tink import hybrid
from tink import mac
from tink import prf
from tink import signature
from tink import streaming_aead

from tink.proto import tink_pb2

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
]
DAEAD_KEY_TYPES = ['AesSivKey']
STREAMING_AEAD_KEY_TYPES = [
    'AesCtrHmacStreamingKey',
    'AesGcmHkdfStreamingKey',
]
HYBRID_PRIVATE_KEY_TYPES = ['EciesAeadHkdfPrivateKey']
MAC_KEY_TYPES = ['HmacKey']
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
ALL_KEY_TYPES = (
    AEAD_KEY_TYPES + DAEAD_KEY_TYPES + STREAMING_AEAD_KEY_TYPES +
    HYBRID_PRIVATE_KEY_TYPES + MAC_KEY_TYPES + SIGNATURE_KEY_TYPES +
    PRF_KEY_TYPES)

# All languages that are supported by a KeyType
SUPPORTED_LANGUAGES = {
    'AesEaxKey': ['cc', 'java', 'python'],
    'AesGcmKey': ['cc', 'java', 'go', 'python'],
    'AesGcmSivKey': ['cc', 'python'],
    'AesCtrHmacAeadKey': ['cc', 'java', 'go', 'python'],
    'ChaCha20Poly1305Key': ['java', 'go'],
    'XChaCha20Poly1305Key': ['cc', 'java', 'go', 'python'],
    'AesSivKey': ['cc', 'java', 'go', 'python'],
    'AesCtrHmacStreamingKey': ['cc', 'java', 'go'],
    'AesGcmHkdfStreamingKey': ['cc', 'java', 'go'],
    'EciesAeadHkdfPrivateKey': ['cc', 'java', 'go', 'python'],
    'HmacKey': ['cc', 'java', 'go', 'python'],
    'EcdsaPrivateKey': ['cc', 'java', 'go', 'python'],
    'Ed25519PrivateKey': ['cc', 'java', 'go', 'python'],
    'RsaSsaPkcs1PrivateKey': ['cc', 'java', 'python'],
    'RsaSsaPssPrivateKey': ['cc', 'java', 'python'],
    'AesCmacPrfKey': ['go', 'python'],
    'HmacPrfKey': ['go', 'python'],
    'HkdfPrfKey': ['go', 'python'],
}

SUPPORTED_LANGUAGES_PER_TYPE_URL = {
    'type.googleapis.com/google.crypto.tink.' + name: langs
    for name, langs in SUPPORTED_LANGUAGES.items()}

# For each KeyType, a list of all KeyTemplate Names that must be supported.
KEY_TEMPLATE_NAMES = {
    'AesEaxKey': ['AES128_EAX', 'AES256_EAX'],
    'AesGcmKey': ['AES128_GCM', 'AES256_GCM'],
    'AesGcmSivKey': ['AES128_GCM_SIV', 'AES256_GCM_SIV'],
    'AesCtrHmacAeadKey': ['AES128_CTR_HMAC_SHA256', 'AES256_CTR_HMAC_SHA256'],
    'ChaCha20Poly1305Key': ['CHACHA20_POLY1305'],
    'XChaCha20Poly1305Key': ['XCHACHA20_POLY1305'],
    'AesSivKey': ['AES256_SIV'],
    'AesCtrHmacStreamingKey': [
        'AES128_CTR_HMAC_SHA256_4KB',
        'AES256_CTR_HMAC_SHA256_4KB',
    ],
    'AesGcmHkdfStreamingKey': [
        'AES128_GCM_HKDF_4KB',
        'AES256_GCM_HKDF_4KB',
        'AES256_GCM_HKDF_1MB',
    ],
    'EciesAeadHkdfPrivateKey': [
        'ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM',
        'ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256'
    ],
    'HmacKey': [
        'HMAC_SHA256_128BITTAG', 'HMAC_SHA256_256BITTAG',
        'HMAC_SHA512_256BITTAG', 'HMAC_SHA512_512BITTAG'
    ],
    'EcdsaPrivateKey': [
        'ECDSA_P256', 'ECDSA_P384', 'ECDSA_P521', 'ECDSA_P256_IEEE_P1363',
        'ECDSA_P384_IEEE_P1363', 'ECDSA_P521_IEEE_P1363'
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
    'AES256_SIV':
        daead.deterministic_aead_key_templates.AES256_SIV,
    'AES128_CTR_HMAC_SHA256_4KB':
        streaming_aead.streaming_aead_key_templates.AES128_CTR_HMAC_SHA256_4KB,
    'AES256_CTR_HMAC_SHA256_4KB':
        streaming_aead.streaming_aead_key_templates.AES256_CTR_HMAC_SHA256_4KB,
    'AES128_GCM_HKDF_4KB':
        streaming_aead.streaming_aead_key_templates.AES128_GCM_HKDF_4KB,
    'AES256_GCM_HKDF_4KB':
        streaming_aead.streaming_aead_key_templates.AES256_GCM_HKDF_4KB,
    'AES256_GCM_HKDF_1MB':
        streaming_aead.streaming_aead_key_templates.AES256_GCM_HKDF_1MB,
    'ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM':
        hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM,
    'ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256':
        hybrid.hybrid_key_templates
        .ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256,
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
    'ECDSA_P521':
        signature.signature_key_templates.ECDSA_P521,
    'ECDSA_P256_IEEE_P1363':
        signature.signature_key_templates.ECDSA_P256_IEEE_P1363,
    'ECDSA_P384_IEEE_P1363':
        signature.signature_key_templates.ECDSA_P384_IEEE_P1363,
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
}


def test_cases(key_types: List[Text]) -> Iterable[Tuple[Text, List[Text]]]:
  """Generates (key_template_name, supported_langs) tuples."""
  for key_type in key_types:
    for key_template_name in KEY_TEMPLATE_NAMES[key_type]:
      yield (key_template_name, SUPPORTED_LANGUAGES[key_type])
