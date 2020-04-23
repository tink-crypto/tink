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

"""Tests for tink.python.tink.core.primitive_set."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from absl.testing import absltest
from tink.proto import tink_pb2
from tink import aead
from tink import core
from tink import mac
from tink.testing import helper


class PrimitiveSetTest(absltest.TestCase):

  def test_primitive_returns_entry(self):
    key = helper.fake_key(key_id=1)
    fake_mac = helper.FakeMac('FakeMac')
    primitive_set = core.new_primitive_set(mac.Mac)
    primitive_set.add_primitive(fake_mac, key)
    entries = primitive_set.primitive(key)
    self.assertLen(entries, 1)
    entry = entries[0]
    self.assertEqual(fake_mac, entry.primitive)
    self.assertEqual(tink_pb2.ENABLED, entry.status)
    self.assertEqual(core.crypto_format.output_prefix(key), entry.identifier)

  def test_unknown_key_returns_empty_list(self):
    primitive_set = core.new_primitive_set(mac.Mac)
    unknown_key = helper.fake_key(key_id=1)
    self.assertEqual(primitive_set.primitive(unknown_key), [])

  def test_primitive_from_identifier_returns_entry(self):
    primitive_set = core.new_primitive_set(mac.Mac)
    key = helper.fake_key(key_id=1)
    fake_mac = helper.FakeMac('FakeMac')
    primitive_set.add_primitive(fake_mac, key)

    ident = core.crypto_format.output_prefix(key)
    entries = primitive_set.primitive_from_identifier(ident)
    self.assertLen(entries, 1)
    entry = entries[0]
    self.assertEqual(fake_mac, entry.primitive)
    self.assertEqual(tink_pb2.ENABLED, entry.status)
    self.assertEqual(ident, entry.identifier)

  def test_list_of_entries_can_be_modified(self):
    primitive_set = core.new_primitive_set(mac.Mac)
    key = helper.fake_key(key_id=1)
    primitive_set.add_primitive(helper.FakeMac('FakeMac'), key)
    entries = primitive_set.primitive(key)
    entries.append('Something')
    self.assertLen(primitive_set.primitive(key), 1)

  def test_primary_returns_primary(self):
    primitive_set = core.new_primitive_set(mac.Mac)
    key = helper.fake_key(key_id=1)
    fake_mac = helper.FakeMac('FakeMac')
    entry = primitive_set.add_primitive(fake_mac, key)
    primitive_set.set_primary(entry)

    entry = primitive_set.primary()
    self.assertEqual(fake_mac, entry.primitive)
    self.assertEqual(tink_pb2.ENABLED, entry.status)
    self.assertEqual(core.crypto_format.output_prefix(key), entry.identifier)

  def test_primary_returns_none(self):
    primitive_set = core.new_primitive_set(mac.Mac)
    primitive_set.add_primitive(
        helper.FakeMac('FakeMac'), helper.fake_key(key_id=1))
    self.assertEqual(primitive_set.primary(), None)

  def test_same_key_id_and_prefix_type(self):
    primitive_set = core.new_primitive_set(mac.Mac)
    key1 = helper.fake_key(key_id=1, status=tink_pb2.ENABLED)
    fake_mac1 = helper.FakeMac('FakeMac1')
    primitive_set.add_primitive(fake_mac1, key1)
    key2 = helper.fake_key(key_id=1, status=tink_pb2.DISABLED)
    fake_mac2 = helper.FakeMac('FakeMac2')
    primitive_set.add_primitive(fake_mac2, key2)

    expected_ident = core.crypto_format.output_prefix(key1)
    entries = primitive_set.primitive(key1)
    self.assertLen(entries, 2)
    self.assertEqual(fake_mac1, entries[0].primitive)
    self.assertEqual(fake_mac2, entries[1].primitive)
    self.assertEqual(tink_pb2.ENABLED, entries[0].status)
    self.assertEqual(tink_pb2.DISABLED, entries[1].status)
    self.assertEqual(expected_ident, entries[0].identifier)
    self.assertEqual(expected_ident, entries[1].identifier)
    self.assertLen(primitive_set.primitive(key2), 2)

  def test_same_key_id_but_different_prefix_type(self):
    primitive_set = core.new_primitive_set(mac.Mac)
    key1 = helper.fake_key(key_id=1, output_prefix_type=tink_pb2.TINK)
    fake_mac1 = helper.FakeMac('FakeMac1')
    primitive_set.add_primitive(fake_mac1, key1)
    key2 = helper.fake_key(key_id=1, output_prefix_type=tink_pb2.LEGACY)
    fake_mac2 = helper.FakeMac('FakeMac2')
    primitive_set.add_primitive(fake_mac2, key2)

    entries1 = primitive_set.primitive(key1)
    self.assertLen(entries1, 1)
    self.assertEqual(fake_mac1, entries1[0].primitive)
    self.assertEqual(tink_pb2.ENABLED, entries1[0].status)
    self.assertEqual(core.crypto_format.output_prefix(key1),
                     entries1[0].identifier)

    entries2 = primitive_set.primitive(key2)
    self.assertLen(entries2, 1)
    self.assertEqual(fake_mac2, entries2[0].primitive)
    self.assertEqual(tink_pb2.ENABLED, entries2[0].status)
    self.assertEqual(core.crypto_format.output_prefix(key2),
                     entries2[0].identifier)

  def test_add_invalid_key_fails(self):
    primitive_set = core.new_primitive_set(mac.Mac)
    key = helper.fake_key()
    key.ClearField('output_prefix_type')
    with self.assertRaisesRegex(core.TinkError, 'invalid OutputPrefixType'):
      primitive_set.add_primitive(helper.FakeMac(), key)

  def test_add_wrong_primitive_fails(self):
    primitive_set = core.new_primitive_set(aead.Aead)
    with self.assertRaisesRegex(core.TinkError,
                                'The primitive is not an instance of '):
      primitive_set.add_primitive(helper.FakeMac(), helper.fake_key())

  def test_primitive_class(self):
    primitive_set = core.new_primitive_set(mac.Mac)
    self.assertEqual(primitive_set.primitive_class(), mac.Mac)

  def test_raw_primitives(self):
    primitive_set = core.new_primitive_set(mac.Mac)
    primitive_set.add_primitive(
        helper.FakeMac('FakeMac1'), helper.fake_key(key_id=1))
    key2 = helper.fake_key(key_id=1, output_prefix_type=tink_pb2.RAW)
    fake_mac2 = helper.FakeMac('FakeMac2')
    primitive_set.add_primitive(fake_mac2, key2)
    key3 = helper.fake_key(
        key_id=3, status=tink_pb2.DISABLED, output_prefix_type=tink_pb2.RAW)
    fake_mac3 = helper.FakeMac('FakeMac3')
    primitive_set.add_primitive(fake_mac3, key3)

    entries = primitive_set.raw_primitives()
    self.assertLen(entries, 2)
    self.assertEqual(fake_mac2, entries[0].primitive)
    self.assertEqual(tink_pb2.ENABLED, entries[0].status)
    self.assertEqual(core.crypto_format.RAW_PREFIX,
                     entries[0].identifier)
    self.assertEqual(fake_mac3, entries[1].primitive)
    self.assertEqual(tink_pb2.DISABLED, entries[1].status)
    self.assertEqual(core.crypto_format.RAW_PREFIX,
                     entries[1].identifier)


if __name__ == '__main__':
  absltest.main()
