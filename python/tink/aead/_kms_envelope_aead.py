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
"""Module for envelope encryption with KMS."""

import struct

from tink.proto import tink_pb2
from tink import core
from tink.aead import _aead

_SUPPORTED_DEK_KEY_TYPES = frozenset({
    'type.googleapis.com/google.crypto.tink.AesGcmKey',
    'type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key',
    'type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey',
    'type.googleapis.com/google.crypto.tink.AesEaxKey',
    'type.googleapis.com/google.crypto.tink.AesGcmSivKey',
})


def is_supported_dek_key_type(type_url: str) -> bool:
  return type_url in _SUPPORTED_DEK_KEY_TYPES


class KmsEnvelopeAead(_aead.Aead):
  """Implements envelope encryption.

  Envelope encryption generates a data encryption key (DEK) which is used
  to encrypt the payload. The DEK is then send to a KMS to be encrypted and
  the encrypted DEK is attached to the ciphertext. In order to decrypt the
  ciphertext, the DEK first has to be decrypted by the KMS, and then the DEK
  can be used to decrypt the ciphertext. For further information see
  https://cloud.google.com/kms/docs/envelope-encryption.

  DEK key template must be a KeyTemplate for any of these Tink AEAD key types
  (any other key template will be rejected):
  * AesGcmKey
  * XChaCha20Poly1305
  * AesCtrHmacAeadKey
  * AesEaxKey
  * AesGcmSivKey

  The ciphertext structure is as follows:
  * Length of the encrypted DEK: 4 bytes (big endian)
  * Encrypted DEK: variable length, specified by the previous 4 bytes
  * AEAD payload: variable length
  """

  # Defines in how many bytes the DEK length will be encoded.
  DEK_LEN_BYTES = 4

  def __init__(self, key_template: tink_pb2.KeyTemplate, remote: _aead.Aead):
    if not is_supported_dek_key_type(key_template.type_url):
      raise core.TinkError(
          'Unsupported DEK key type: %s' % key_template.type_url
      )
    # Create a dek to make sure that it works, so that KmsEnvelopeAead already
    # fails when it is created, and not just when it is used.
    # The C++ implementation does the same check, and we want this
    # implementation to be consistent with the C++ implementation.
    _ = core.Registry.new_key_data(key_template)

    self.key_template = key_template
    self.remote_aead = remote

  def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
    # Get new key from template
    dek = core.Registry.new_key_data(self.key_template)
    dek_aead = core.Registry.primitive(dek, _aead.Aead)

    # Encrypt plaintext
    ciphertext = dek_aead.encrypt(plaintext, associated_data)

    # Wrap DEK key values with remote
    encrypted_dek = self.remote_aead.encrypt(dek.value, b'')

    # Construct ciphertext, DEK length encoded as big endian
    enc_dek_len = struct.pack('>I', len(encrypted_dek))
    return enc_dek_len + encrypted_dek + ciphertext

  def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes:
    ct_len = len(ciphertext)

    # Recover DEK length
    if ct_len < self.DEK_LEN_BYTES:
      raise core.TinkError

    dek_len = struct.unpack('>I', ciphertext[0:self.DEK_LEN_BYTES])[0]

    # Basic check if DEK length can be valid.
    if dek_len > (ct_len - self.DEK_LEN_BYTES) or dek_len < 0:
      raise core.TinkError

    # Decrypt DEK with remote AEAD
    encrypted_dek_bytes = ciphertext[self.DEK_LEN_BYTES:self.DEK_LEN_BYTES +
                                     dek_len]
    dek_bytes = self.remote_aead.decrypt(encrypted_dek_bytes, b'')

    # Get AEAD primitive based on DEK
    dek = tink_pb2.KeyData(
        type_url=self.key_template.type_url,
        value=dek_bytes,
        key_material_type=tink_pb2.KeyData.SYMMETRIC,
    )
    dek_aead = core.Registry.primitive(dek, _aead.Aead)

    # Extract ciphertext payload and decrypt
    ct_bytes = ciphertext[self.DEK_LEN_BYTES + dek_len:]

    return dek_aead.decrypt(ct_bytes, associated_data)
