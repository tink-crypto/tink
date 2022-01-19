# Copyright 2019 Google LLC
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

"""Tests for tink.python.tink.deterministic_aead_key_manager."""

from absl.testing import absltest

from tink.proto import aes_siv_pb2
from tink.proto import tink_pb2
import tink
from tink import core
from tink import daead


def setUpModule():
  daead.register()


class DeterministicAeadKeyManagerTest(absltest.TestCase):

  def test_new_key_data(self):
    key_template = daead.deterministic_aead_key_templates.AES256_SIV
    key_manager = core.Registry.key_manager(key_template.type_url)
    key_data = key_manager.new_key_data(key_template)
    self.assertEqual(key_data.type_url, key_manager.key_type())
    self.assertEqual(key_data.key_material_type, tink_pb2.KeyData.SYMMETRIC)
    key = aes_siv_pb2.AesSivKey.FromString(key_data.value)
    self.assertEqual(key.version, 0)
    self.assertLen(key.key_value, 64)

  def test_invalid_params_throw_exception(self):
    key_template = (daead.deterministic_aead_key_templates
                    .create_aes_siv_key_template(63))
    with self.assertRaises(core.TinkError):
      tink.new_keyset_handle(key_template)

  def test_encrypt_decrypt(self):
    keyset_handle = tink.new_keyset_handle(
        daead.deterministic_aead_key_templates.AES256_SIV)
    daead_primitive = keyset_handle.primitive(daead.DeterministicAead)
    plaintext = b'plaintext'
    associated_data = b'associated_data'
    ciphertext = daead_primitive.encrypt_deterministically(
        plaintext, associated_data)
    self.assertEqual(
        daead_primitive.decrypt_deterministically(ciphertext, associated_data),
        plaintext)

  def test_invalid_decrypt_raises_error(self):
    keyset_handle = tink.new_keyset_handle(
        daead.deterministic_aead_key_templates.AES256_SIV)
    daead_primitive = keyset_handle.primitive(daead.DeterministicAead)
    with self.assertRaises(core.TinkError):
      daead_primitive.decrypt_deterministically(
          b'bad ciphertext', b'associated_data')


if __name__ == '__main__':
  absltest.main()
