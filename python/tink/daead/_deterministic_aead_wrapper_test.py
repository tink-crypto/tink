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

"""Tests for tink.python.tink.aead_wrapper."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from absl.testing import absltest
from tink.proto import tink_pb2
from tink import core
from tink import daead
from tink.testing import helper


def setUpModule():
  daead.register()


class AeadWrapperTest(absltest.TestCase):

  def new_primitive_key_pair(self, key_id, output_prefix_type):
    fake_key = helper.fake_key(
        key_id=key_id, output_prefix_type=output_prefix_type)
    fake_aead = helper.FakeDeterministicAead(
        'fakeDeterministicAead {}'.format(key_id))
    return fake_aead, fake_key

  def test_encrypt_decrypt(self):
    primitive, key = self.new_primitive_key_pair(1234, tink_pb2.TINK)
    pset = core.new_primitive_set(daead.DeterministicAead)
    entry = pset.add_primitive(primitive, key)
    pset.set_primary(entry)

    wrapped_daead = core.Registry.wrap(pset)

    plaintext = b'plaintext'
    associated_data = b'associated_data'
    ciphertext = wrapped_daead.encrypt_deterministically(
        plaintext, associated_data)
    self.assertEqual(
        wrapped_daead.decrypt_deterministically(ciphertext, associated_data),
        plaintext)

  def test_encrypt_decrypt_with_key_rotation(self):
    primitive, key = self.new_primitive_key_pair(1234, tink_pb2.TINK)
    pset = core.new_primitive_set(daead.DeterministicAead)
    entry = pset.add_primitive(primitive, key)
    pset.set_primary(entry)
    wrapped_daead = core.Registry.wrap(pset)
    ciphertext = wrapped_daead.encrypt_deterministically(
        b'plaintext', b'associated_data')

    new_primitive, new_key = self.new_primitive_key_pair(5678, tink_pb2.TINK)
    new_entry = pset.add_primitive(new_primitive, new_key)
    pset.set_primary(new_entry)
    new_ciphertext = wrapped_daead.encrypt_deterministically(
        b'new_plaintext', b'new_associated_data')

    self.assertEqual(
        wrapped_daead.decrypt_deterministically(ciphertext, b'associated_data'),
        b'plaintext')
    self.assertEqual(
        wrapped_daead.decrypt_deterministically(new_ciphertext,
                                                b'new_associated_data'),
        b'new_plaintext')

  def test_encrypt_decrypt_with_key_rotation_from_raw(self):
    primitive, raw_key = self.new_primitive_key_pair(1234, tink_pb2.RAW)
    old_raw_ciphertext = primitive.encrypt_deterministically(
        b'plaintext', b'associated_data')

    pset = core.new_primitive_set(daead.DeterministicAead)
    pset.add_primitive(primitive, raw_key)
    new_primitive, new_key = self.new_primitive_key_pair(5678, tink_pb2.TINK)
    new_entry = pset.add_primitive(new_primitive, new_key)
    pset.set_primary(new_entry)
    wrapped_daead = core.Registry.wrap(pset)
    new_ciphertext = wrapped_daead.encrypt_deterministically(
        b'new_plaintext', b'new_associated_data')

    self.assertEqual(
        wrapped_daead.decrypt_deterministically(old_raw_ciphertext,
                                                b'associated_data'),
        b'plaintext')
    self.assertEqual(
        wrapped_daead.decrypt_deterministically(new_ciphertext,
                                                b'new_associated_data'),
        b'new_plaintext')

  def test_encrypt_decrypt_two_raw_keys(self):
    primitive1, raw_key1 = self.new_primitive_key_pair(1234, tink_pb2.RAW)
    primitive2, raw_key2 = self.new_primitive_key_pair(5678, tink_pb2.RAW)
    raw_ciphertext1 = primitive1.encrypt_deterministically(
        b'plaintext1', b'associated_data1')
    raw_ciphertext2 = primitive2.encrypt_deterministically(
        b'plaintext2', b'associated_data2')

    pset = core.new_primitive_set(daead.DeterministicAead)
    pset.add_primitive(primitive1, raw_key1)
    pset.set_primary(pset.add_primitive(primitive2, raw_key2))
    wrapped_daead = core.Registry.wrap(pset)

    self.assertEqual(
        wrapped_daead.decrypt_deterministically(raw_ciphertext1,
                                                b'associated_data1'),
        b'plaintext1')
    self.assertEqual(
        wrapped_daead.decrypt_deterministically(raw_ciphertext2,
                                                b'associated_data2'),
        b'plaintext2')
    self.assertEqual(
        wrapped_daead.decrypt_deterministically(
            wrapped_daead.encrypt_deterministically(b'plaintext',
                                                    b'associated_data'),
            b'associated_data'), b'plaintext')

  def test_decrypt_unknown_ciphertext_fails(self):
    unknown_primitive = helper.FakeDeterministicAead(
        'unknownFakeDeterministicAead')
    unknown_ciphertext = unknown_primitive.encrypt_deterministically(
        b'plaintext', b'associated_data')

    pset = core.new_primitive_set(daead.DeterministicAead)
    primitive, raw_key = self.new_primitive_key_pair(1234, tink_pb2.RAW)
    new_primitive, new_key = self.new_primitive_key_pair(5678, tink_pb2.TINK)
    pset.add_primitive(primitive, raw_key)
    new_entry = pset.add_primitive(new_primitive, new_key)
    pset.set_primary(new_entry)
    wrapped_daead = core.Registry.wrap(pset)

    with self.assertRaisesRegex(core.TinkError, 'Decryption failed'):
      wrapped_daead.decrypt_deterministically(unknown_ciphertext,
                                              b'associated_data')

  def test_decrypt_wrong_associated_data_fails(self):
    primitive, key = self.new_primitive_key_pair(1234, tink_pb2.TINK)
    pset = core.new_primitive_set(daead.DeterministicAead)
    entry = pset.add_primitive(primitive, key)
    pset.set_primary(entry)
    wrapped_daead = core.Registry.wrap(pset)

    ciphertext = wrapped_daead.encrypt_deterministically(
        b'plaintext', b'associated_data')
    with self.assertRaisesRegex(core.TinkError, 'Decryption failed'):
      wrapped_daead.decrypt_deterministically(ciphertext,
                                              b'wrong_associated_data')


if __name__ == '__main__':
  absltest.main()
