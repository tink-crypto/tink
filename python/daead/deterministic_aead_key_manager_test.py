# Copyright 2019 Google LLC.
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

"""Tests for tink.python.aead_key_manager."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from absl.testing import absltest
from tink.proto import aes_siv_pb2
from tink.proto import tink_pb2
from tink.python import tink_config
from tink.python.core import tink_error
from tink.python.daead import deterministic_aead
from tink.python.daead import deterministic_aead_key_manager
from tink.python.daead import deterministic_aead_key_templates


def setUpModule():
  tink_config.register()


class DeterministicAeadKeyManagerTest(absltest.TestCase):

  def setUp(self):
    super(DeterministicAeadKeyManagerTest, self).setUp()
    self.key_manager = deterministic_aead_key_manager.from_cc_registry(
        'type.googleapis.com/google.crypto.tink.AesSivKey')

  def test_primitive_class(self):
    self.assertEqual(self.key_manager.primitive_class(),
                     deterministic_aead.DeterministicAead)

  def test_key_type(self):
    self.assertEqual(self.key_manager.key_type(),
                     'type.googleapis.com/google.crypto.tink.AesSivKey')

  def test_new_key_data(self):
    key_template = deterministic_aead_key_templates.AES256_SIV
    key_data = self.key_manager.new_key_data(key_template)
    self.assertEqual(key_data.type_url, self.key_manager.key_type())
    self.assertEqual(key_data.key_material_type, tink_pb2.KeyData.SYMMETRIC)
    key = aes_siv_pb2.AesSivKey()
    key.ParseFromString(key_data.value)
    self.assertEqual(key.version, 0)
    self.assertLen(key.key_value, 64)

  def test_invalid_params_throw_exception(self):
    key_template = deterministic_aead_key_templates.create_aes_siv_key_template(
        63)
    with self.assertRaisesRegex(tink_error.TinkError,
                                'Invalid AesSivKeyFormat'):
      self.key_manager.new_key_data(key_template)

  def test_encrypt_decrypt(self):
    daead_primitive = self.key_manager.primitive(
        self.key_manager.new_key_data(
            deterministic_aead_key_templates.AES256_SIV))
    plaintext = b'plaintext'
    associated_data = b'associated_data'
    ciphertext = daead_primitive.encrypt_deterministically(
        plaintext, associated_data)
    self.assertEqual(
        daead_primitive.decrypt_deterministically(ciphertext, associated_data),
        plaintext)


if __name__ == '__main__':
  absltest.main()
