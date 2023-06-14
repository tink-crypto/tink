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
"""Tests for tink.python.tink.aead.aead."""

import struct

from absl.testing import absltest
from absl.testing import parameterized

from tink.proto import aes_gcm_pb2
import tink
from tink import aead
from tink import core
from tink import mac


def setUpModule():
  aead.register()


class KmsEnvelopeAeadTest(parameterized.TestCase):

  @parameterized.parameters([
      aead.aead_key_templates.AES128_EAX,
      aead.aead_key_templates.AES256_EAX,
      aead.aead_key_templates.AES128_GCM,
      aead.aead_key_templates.AES256_GCM,
      aead.aead_key_templates.AES128_GCM_SIV,
      aead.aead_key_templates.AES256_GCM_SIV,
      aead.aead_key_templates.AES128_CTR_HMAC_SHA256,
      aead.aead_key_templates.AES256_CTR_HMAC_SHA256,
      aead.aead_key_templates.XCHACHA20_POLY1305,
  ])
  def test_encrypt_decrypt(self, dek_template):
    keyset_handle = tink.new_keyset_handle(dek_template)
    remote_aead = keyset_handle.primitive(aead.Aead)
    env_aead = aead.KmsEnvelopeAead(dek_template, remote_aead)

    plaintext = b'plaintext'
    associated_data = b'associated_data'
    ciphertext = env_aead.encrypt(plaintext, associated_data)
    self.assertEqual(plaintext, env_aead.decrypt(ciphertext, associated_data))

    with self.assertRaises(core.TinkError):
      _ = env_aead.decrypt(ciphertext, b'invalid_associated_data')

  def test_encrypt_decrypt_missing_ad(self):
    key_template = aead.aead_key_templates.AES256_GCM
    keyset_handle = tink.new_keyset_handle(key_template)
    remote_aead = keyset_handle.primitive(aead.Aead)
    env_aead = aead.KmsEnvelopeAead(key_template, remote_aead)

    plaintext = b'helloworld'
    ciphertext = env_aead.encrypt(plaintext, b'envelope_ad')
    with self.assertRaises(core.TinkError):
      _ = env_aead.decrypt(ciphertext, b'')

  def test_invalid_dek_template_fails(self):
    key_template = aead.aead_key_templates.AES256_GCM
    keyset_handle = tink.new_keyset_handle(key_template)
    remote_aead = keyset_handle.primitive(aead.Aead)

    with self.assertRaises(tink.TinkError):
      aead.KmsEnvelopeAead(
          mac.mac_key_templates.HMAC_SHA256_128BITTAG, remote_aead)

  def test_corrupted_ciphertext(self):
    key_template = aead.aead_key_templates.AES256_GCM
    keyset_handle = tink.new_keyset_handle(key_template)
    remote_aead = keyset_handle.primitive(aead.Aead)
    env_aead = aead.KmsEnvelopeAead(key_template, remote_aead)

    plaintext = b'helloworld'
    ciphertext = bytearray(env_aead.encrypt(plaintext, b'some ad'))
    ciphertext[-1] ^= 0x1
    corrupted_ciphertext = bytes(ciphertext)

    with self.assertRaises(core.TinkError):
      _ = env_aead.decrypt(corrupted_ciphertext, b'some ad')

  def test_corrupted_dek(self):
    key_template = aead.aead_key_templates.AES256_GCM
    keyset_handle = tink.new_keyset_handle(key_template)
    remote_aead = keyset_handle.primitive(aead.Aead)
    env_aead = aead.KmsEnvelopeAead(key_template, remote_aead)

    plaintext = b'helloworld'
    ciphertext = bytearray(env_aead.encrypt(plaintext, b'some ad'))
    ciphertext[4] ^= 0x1
    corrupted_ciphertext = bytes(ciphertext)

    with self.assertRaises(core.TinkError):
      _ = env_aead.decrypt(corrupted_ciphertext, b'some ad')

  def test_ciphertext_too_short(self):
    key_template = aead.aead_key_templates.AES256_GCM
    keyset_handle = tink.new_keyset_handle(key_template)
    remote_aead = keyset_handle.primitive(aead.Aead)
    env_aead = aead.KmsEnvelopeAead(key_template, remote_aead)

    with self.assertRaises(core.TinkError):
      _ = env_aead.decrypt(b'foo', b'some ad')

  def test_malformed_dek_length(self):
    key_template = aead.aead_key_templates.AES256_GCM
    keyset_handle = tink.new_keyset_handle(key_template)
    remote_aead = keyset_handle.primitive(aead.Aead)
    env_aead = aead.KmsEnvelopeAead(key_template, remote_aead)

    plaintext = b'helloworld'
    ciphertext = bytearray(env_aead.encrypt(plaintext, b'some ad'))
    ciphertext[0:3] = [0xff, 0xff, 0xff, 0xff]
    corrupted_ciphertext = bytes(ciphertext)

    with self.assertRaises(core.TinkError):
      _ = env_aead.decrypt(corrupted_ciphertext, b'some ad')

    ciphertext[0:3] = [0, 0, 0, 0]
    corrupted_ciphertext = bytes(ciphertext)

    with self.assertRaises(core.TinkError):
      _ = env_aead.decrypt(corrupted_ciphertext, b'some ad')

  def test_ciphertext_wire_format(self):
    key_template = aead.aead_key_templates.AES256_GCM
    keyset_handle = tink.new_keyset_handle(key_template)
    remote_aead = keyset_handle.primitive(aead.Aead)
    env_aead = aead.KmsEnvelopeAead(key_template, remote_aead)

    plaintext = b'helloworld'
    ciphertext = bytearray(env_aead.encrypt(plaintext, b'some ad'))

    # test that ciphertext has the wire format described here:
    # https://developers.google.com/tink/wire-format#envelope_encryption
    dek_len = struct.unpack('>I',
                            ciphertext[0:aead.KmsEnvelopeAead.DEK_LEN_BYTES])[0]
    encrypted_dek_bytes = bytes(ciphertext[
        aead.KmsEnvelopeAead.DEK_LEN_BYTES:aead.KmsEnvelopeAead.DEK_LEN_BYTES +
        dek_len])
    dek_bytes = remote_aead.decrypt(encrypted_dek_bytes, b'')

    # Try to deserialize key
    key = aes_gcm_pb2.AesGcmKey.FromString(dek_bytes)
    self.assertLen(key.key_value, 32)


if __name__ == '__main__':
  absltest.main()
