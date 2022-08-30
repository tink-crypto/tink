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
"""This file gives an overview of the key types supported in Tink.

This file is the authorative reference of which key types Tink currently
understands in which language, and for which primitive. The correctness of this
file is checked by the cross language tests.
"""

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
HYBRID_PRIVATE_KEY_TYPES = ['EciesAeadHkdfPrivateKey', 'HpkePrivateKey']
MAC_KEY_TYPES = [
    'AesCmacKey',
    'HmacKey',
]
PRIVATE_SIGNATURE_KEY_TYPES = [
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
JWT_PRIVATE_SIGNATURE_KEY_TYPES = [
    'JwtEcdsaPrivateKey',
    'JwtRsaSsaPkcs1PrivateKey',
    'JwtRsaSsaPssPrivateKey',
]

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
    'HpkePrivateKey': ['cc', 'java', 'go', 'python'],
    'AesCmacKey': ['cc', 'java', 'go', 'python'],
    'HmacKey': ['cc', 'java', 'go', 'python'],
    'EcdsaPrivateKey': ['cc', 'java', 'go', 'python'],
    'Ed25519PrivateKey': ['cc', 'java', 'go', 'python'],
    'RsaSsaPkcs1PrivateKey': ['cc', 'java', 'go', 'python'],
    'RsaSsaPssPrivateKey': ['cc', 'java', 'python'],
    'AesCmacPrfKey': ['cc', 'java', 'go', 'python'],
    'HmacPrfKey': ['cc', 'java', 'go', 'python'],
    'HkdfPrfKey': ['cc', 'java', 'go', 'python'],
    'JwtHmacKey': ['cc', 'java', 'go', 'python'],
    'JwtEcdsaPrivateKey': ['cc', 'java', 'go', 'python'],
    'JwtRsaSsaPkcs1PrivateKey': ['cc', 'java', 'go', 'python'],
    'JwtRsaSsaPssPrivateKey': ['cc', 'java', 'go', 'python'],
}
