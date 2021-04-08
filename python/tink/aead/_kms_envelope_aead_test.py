# Copyright 2020 Google LLC.
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

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import struct
from absl.testing import absltest

from tink.proto import aes_gcm_pb2
import tink
from tink import aead
from tink import core


def setUpModule():
  aead.register()


class KmsEnvelopeAeadTest(absltest.TestCase):

  def test_encrypt_decrypt(self):
    key_template = aead.aead_key_templates.AES256_GCM
    keyset_handle = tink.new_keyset_handle(key_template)
    remote_aead = keyset_handle.primitive(aead.Aead)
    env_aead = aead.KmsEnvelopeAead(key_template, remote_aead)

    plaintext = b'helloworld'
    ciphertext = env_aead.encrypt(plaintext, b'')
    self.assertEqual(plaintext, env_aead.decrypt(ciphertext, b''))

  def test_encrypt_decrypt_missing_ad(self):
    key_template = aead.aead_key_templates.AES256_GCM
    keyset_handle = tink.new_keyset_handle(key_template)
    remote_aead = keyset_handle.primitive(aead.Aead)
    env_aead = aead.KmsEnvelopeAead(key_template, remote_aead)

    plaintext = b'helloworld'
    ciphertext = env_aead.encrypt(plaintext, b'envelope_ad')
    with self.assertRaises(core.TinkError):
      plaintext = env_aead.decrypt(ciphertext, b'')

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
      plaintext = env_aead.decrypt(corrupted_ciphertext, b'some ad')

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
      plaintext = env_aead.decrypt(corrupted_ciphertext, b'some ad')

  def test_ciphertext_too_short(self):
    key_template = aead.aead_key_templates.AES256_GCM
    keyset_handle = tink.new_keyset_handle(key_template)
    remote_aead = keyset_handle.primitive(aead.Aead)
    env_aead = aead.KmsEnvelopeAead(key_template, remote_aead)

    with self.assertRaises(core.TinkError):
      env_aead.decrypt(b'foo', b'some ad')

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
      plaintext = env_aead.decrypt(corrupted_ciphertext, b'some ad')

    ciphertext[0:3] = [0, 0, 0, 0]
    corrupted_ciphertext = bytes(ciphertext)

    with self.assertRaises(core.TinkError):
      plaintext = env_aead.decrypt(corrupted_ciphertext, b'some ad')

  def test_dek_extraction(self):
    key_template = aead.aead_key_templates.AES256_GCM
    keyset_handle = tink.new_keyset_handle(key_template)
    remote_aead = keyset_handle.primitive(aead.Aead)
    env_aead = aead.KmsEnvelopeAead(key_template, remote_aead)

    plaintext = b'helloworld'
    ciphertext = bytearray(env_aead.encrypt(plaintext, b'some ad'))

    # Decrypt DEK
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
