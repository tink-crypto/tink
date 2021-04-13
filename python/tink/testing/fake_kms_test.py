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
"""Tests for tink.python.tink.testing._fake_kms."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from absl.testing import absltest
import tink
from tink import aead
from tink.testing import fake_kms


KEY_URI = (
    'fake-kms://CL3oi0kSVwpMCjB0eXBlLmdvb2dsZWFwaXMuY29tL2dvb2dsZS5jcnlwdG8'
    'udGluay5BZXNFYXhLZXkSFhICCBAaEPFnQNgtxEG0vEek8bBfgL8YARABGL3oi0kgAQ')


def setUpModule():
  aead.register()
  fake_kms.register_client()


class FakeKmsTest(absltest.TestCase):

  def test_fake_kms_aead_encrypt_decrypt(self):
    template = aead.aead_key_templates.create_kms_aead_key_template(
        key_uri=KEY_URI)
    keyset_handle = tink.new_keyset_handle(template)
    primitive = keyset_handle.primitive(aead.Aead)
    plaintext = b'plaintext'
    associated_data = b'associated_data'
    ciphertext = primitive.encrypt(plaintext, associated_data)
    self.assertEqual(primitive.decrypt(ciphertext, associated_data), plaintext)

  def test_fake_kms_envelope_encrypt_decrypt(self):
    template = aead.aead_key_templates.create_kms_envelope_aead_key_template(
        kek_uri=KEY_URI,
        dek_template=aead.aead_key_templates.AES128_GCM)
    keyset_handle = tink.new_keyset_handle(template)
    primitive = keyset_handle.primitive(aead.Aead)
    plaintext = b'plaintext'
    associated_data = b'associated_data'
    ciphertext = primitive.encrypt(plaintext, associated_data)
    self.assertEqual(primitive.decrypt(ciphertext, associated_data), plaintext)


if __name__ == '__main__':
  absltest.main()
