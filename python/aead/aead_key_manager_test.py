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
from tink.proto import aes_eax_pb2
from tink.proto import aes_gcm_pb2
from tink.proto import tink_pb2
from tink.python import tink_config
from tink.python.aead import aead
from tink.python.aead import aead_key_manager
from tink.python.core import tink_error


def setUpModule():
  tink_config.register()


class AeadKeyManagerTest(absltest.TestCase):

  def setUp(self):
    super(AeadKeyManagerTest, self).setUp()
    self.key_manager_eax = aead_key_manager.from_cc_registry(
        'type.googleapis.com/google.crypto.tink.AesEaxKey')
    self.key_manager_gcm = aead_key_manager.from_cc_registry(
        'type.googleapis.com/google.crypto.tink.AesGcmKey')

  def new_aes_eax_key_template(self, iv_size, key_size):
    key_format = aes_eax_pb2.AesEaxKeyFormat()
    key_format.params.iv_size = iv_size
    key_format.key_size = key_size
    key_template = tink_pb2.KeyTemplate()
    key_template.type_url = ('type.googleapis.com/google.crypto.tink.AesEaxKey')
    key_template.value = key_format.SerializeToString()
    return key_template

  def new_aes_gcm_key_template(self, key_size):
    key_format = aes_gcm_pb2.AesGcmKeyFormat()
    key_format.key_size = key_size
    key_template = tink_pb2.KeyTemplate()
    key_template.type_url = ('type.googleapis.com/google.crypto.tink.AesGcmKey')
    key_template.value = key_format.SerializeToString()
    return key_template

  def test_primitive_class(self):
    self.assertEqual(self.key_manager_eax.primitive_class(), aead.Aead)
    self.assertEqual(self.key_manager_gcm.primitive_class(), aead.Aead)

  def test_key_type(self):
    self.assertEqual(self.key_manager_eax.key_type(),
                     'type.googleapis.com/google.crypto.tink.AesEaxKey')
    self.assertEqual(self.key_manager_gcm.key_type(),
                     'type.googleapis.com/google.crypto.tink.AesGcmKey')

  def test_new_key_data(self):
    # AES EAX
    key_template = self.new_aes_eax_key_template(12, 16)
    key_data = self.key_manager_eax.new_key_data(key_template)
    self.assertEqual(key_data.type_url, self.key_manager_eax.key_type())
    self.assertEqual(key_data.key_material_type, tink_pb2.KeyData.SYMMETRIC)
    key = aes_eax_pb2.AesEaxKey()
    key.ParseFromString(key_data.value)
    self.assertEqual(key.version, 0)
    self.assertEqual(key.params.iv_size, 12)
    self.assertLen(key.key_value, 16)

    # AES GCM
    key_template = self.new_aes_gcm_key_template(16)
    key_data = self.key_manager_gcm.new_key_data(key_template)
    self.assertEqual(key_data.type_url, self.key_manager_gcm.key_type())
    self.assertEqual(key_data.key_material_type, tink_pb2.KeyData.SYMMETRIC)
    key = aes_gcm_pb2.AesGcmKey()
    key.ParseFromString(key_data.value)
    self.assertEqual(key.version, 0)
    self.assertLen(key.key_value, 16)

  def test_invalid_params_throw_exception(self):
    key_template = self.new_aes_eax_key_template(9, 16)
    with self.assertRaisesRegex(tink_error.TinkError,
                                'Invalid AesEaxKeyFormat'):
      self.key_manager_eax.new_key_data(key_template)

    key_template = self.new_aes_gcm_key_template(17)
    with self.assertRaisesRegex(tink_error.TinkError,
                                'supported sizes: 16 or 32 bytes'):
      self.key_manager_gcm.new_key_data(key_template)

  def test_encrypt_decrypt(self):
    # AES EAX
    primitive = self.key_manager_eax.primitive(
        self.key_manager_eax.new_key_data(
            self.new_aes_eax_key_template(12, 16)))
    plaintext = b'plaintext'
    associated_data = b'associated_data'
    ciphertext = primitive.encrypt(plaintext, associated_data)
    self.assertEqual(primitive.decrypt(ciphertext, associated_data), plaintext)

    # AES GCM
    primitive = self.key_manager_gcm.primitive(
        self.key_manager_gcm.new_key_data(self.new_aes_gcm_key_template(16)))
    plaintext = b'plaintext'
    associated_data = b'associated_data'
    ciphertext = primitive.encrypt(plaintext, associated_data)
    self.assertEqual(primitive.decrypt(ciphertext, associated_data), plaintext)

  def test_invalid_decrypt_raises_error(self):
    primitive = self.key_manager_eax.primitive(
        self.key_manager_eax.new_key_data(
            self.new_aes_eax_key_template(12, 16)))
    with self.assertRaisesRegex(tink_error.TinkError, 'Ciphertext too short'):
      primitive.decrypt(b'invalid ciphertext', 'ad')


if __name__ == '__main__':
  absltest.main()
