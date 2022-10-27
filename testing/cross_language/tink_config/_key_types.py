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

from tink import aead
from tink import daead
from tink import hybrid
from tink import jwt
from tink import mac
from tink import prf
from tink import signature
from tink import streaming_aead

# Map from the primitives to the KeyTypes (without the prefix
# 'type.googleapis.com/google.crypto.tink.')
KEY_TYPES = {
    aead.Aead: (
        'AesEaxKey',
        'AesGcmKey',
        'AesGcmSivKey',
        'AesCtrHmacAeadKey',
        'ChaCha20Poly1305Key',
        'XChaCha20Poly1305Key',
        'KmsAeadKey',
        'KmsEnvelopeAeadKey',
    ),
    daead.DeterministicAead: ('AesSivKey',),
    streaming_aead.StreamingAead: (
        'AesCtrHmacStreamingKey',
        'AesGcmHkdfStreamingKey',
    ),
    hybrid.HybridDecrypt: ('EciesAeadHkdfPrivateKey', 'HpkePrivateKey'),
    hybrid.HybridEncrypt: ('EciesAeadHkdfPublicKey', 'HpkePublicKey'),
    mac.Mac: (
        'AesCmacKey',
        'HmacKey',
    ),
    signature.PublicKeySign: (
        'EcdsaPrivateKey',
        'Ed25519PrivateKey',
        'RsaSsaPkcs1PrivateKey',
        'RsaSsaPssPrivateKey',
    ),
    signature.PublicKeyVerify: (
        'EcdsaPublicKey',
        'Ed25519PublicKey',
        'RsaSsaPkcs1PublicKey',
        'RsaSsaPssPublicKey',
    ),
    prf.PrfSet: (
        'AesCmacPrfKey',
        'HmacPrfKey',
        'HkdfPrfKey',
    ),
    jwt.JwtMac: ('JwtHmacKey',),
    jwt.JwtPublicKeySign: (
        'JwtEcdsaPrivateKey',
        'JwtRsaSsaPkcs1PrivateKey',
        'JwtRsaSsaPssPrivateKey',
    ),
    jwt.JwtPublicKeyVerify: (
        'JwtEcdsaPublicKey',
        'JwtRsaSsaPkcs1PublicKey',
        'JwtRsaSsaPssPublicKey',
    )
}

# Map from Asymmetric Private Primitive to Asymmetric Public Primitive
PRIVATE_TO_PUBLIC_PRIMITIVE = {
    hybrid.HybridDecrypt: hybrid.HybridEncrypt,
    signature.PublicKeySign: signature.PublicKeyVerify,
    jwt.JwtPublicKeySign: jwt.JwtPublicKeyVerify,
}

# Map from Private Key Types to Public Key Types
PRIVATE_TO_PUBLIC_KEY = {
    'EciesAeadHkdfPrivateKey': 'EciesAeadHkdfPublicKey',
    'HpkePrivateKey': 'HpkePublicKey',
    'EcdsaPrivateKey': 'EcdsaPublicKey',
    'Ed25519PrivateKey': 'Ed25519PublicKey',
    'RsaSsaPkcs1PrivateKey': 'RsaSsaPkcs1PublicKey',
    'RsaSsaPssPrivateKey': 'RsaSsaPssPublicKey',
    'JwtEcdsaPrivateKey': 'JwtEcdsaPublicKey',
    'JwtRsaSsaPkcs1PrivateKey': 'JwtRsaSsaPkcs1PublicKey',
    'JwtRsaSsaPssPrivateKey': 'JwtRsaSsaPssPublicKey',
}

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
    'EciesAeadHkdfPublicKey': ['cc', 'java', 'go', 'python'],
    'HpkePrivateKey': ['cc', 'java', 'go', 'python'],
    'HpkePublicKey': ['cc', 'java', 'go', 'python'],
    'AesCmacKey': ['cc', 'java', 'go', 'python'],
    'HmacKey': ['cc', 'java', 'go', 'python'],
    'EcdsaPrivateKey': ['cc', 'java', 'go', 'python'],
    'EcdsaPublicKey': ['cc', 'java', 'go', 'python'],
    'Ed25519PrivateKey': ['cc', 'java', 'go', 'python'],
    'Ed25519PublicKey': ['cc', 'java', 'go', 'python'],
    'RsaSsaPkcs1PrivateKey': ['cc', 'java', 'go', 'python'],
    'RsaSsaPkcs1PublicKey': ['cc', 'java', 'go', 'python'],
    'RsaSsaPssPrivateKey': ['cc', 'java', 'go', 'python'],
    'RsaSsaPssPublicKey': ['cc', 'java', 'go', 'python'],
    'AesCmacPrfKey': ['cc', 'java', 'go', 'python'],
    'HmacPrfKey': ['cc', 'java', 'go', 'python'],
    'HkdfPrfKey': ['cc', 'java', 'go', 'python'],
    'JwtHmacKey': ['cc', 'java', 'go', 'python'],
    'JwtEcdsaPrivateKey': ['cc', 'java', 'go', 'python'],
    'JwtEcdsaPublicKey': ['cc', 'java', 'go', 'python'],
    'JwtRsaSsaPkcs1PrivateKey': ['cc', 'java', 'go', 'python'],
    'JwtRsaSsaPkcs1PublicKey': ['cc', 'java', 'go', 'python'],
    'JwtRsaSsaPssPrivateKey': ['cc', 'java', 'go', 'python'],
    'JwtRsaSsaPssPublicKey': ['cc', 'java', 'go', 'python'],
}
