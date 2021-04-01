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
# Placeholder for import for type annotations
from __future__ import print_function

from absl.testing import absltest
from tink.proto import tink_pb2
from tink import aead
from tink import core
from tink import mac
from tink.testing import helper


MAC_TEMPLATE = mac.mac_key_templates.HMAC_SHA256_128BITTAG


def setUpModule():
  mac.register()


def new_key(
    template: tink_pb2.KeyTemplate,
    key_id: int,
    output_prefix_type: tink_pb2.OutputPrefixType = tink_pb2.TINK,
    status: tink_pb2.KeyStatusType = tink_pb2.ENABLED
) -> tink_pb2.Keyset.Key:
  return tink_pb2.Keyset.Key(
      key_data=core.Registry.new_key_data(template),
      key_id=key_id,
      status=status,
      output_prefix_type=output_prefix_type)


class PrimitiveSetTest(absltest.TestCase):

  def test_primitive_returns_entry(self):
    key = new_key(MAC_TEMPLATE, key_id=1)
    primitive = core.Registry.primitive(key.key_data, mac.Mac)
    primitive_set = core.new_primitive_set(mac.Mac)
    primitive_set.add_primitive(primitive, key)
    entries = primitive_set.primitive(key)
    self.assertLen(entries, 1)
    entry = entries[0]
    self.assertEqual(primitive, entry.primitive)
    self.assertEqual(tink_pb2.ENABLED, entry.status)
    self.assertEqual(core.crypto_format.output_prefix(key), entry.identifier)
    self.assertEqual(1, entry.key_id)

  def test_unknown_key_returns_empty_list(self):
    primitive_set = core.new_primitive_set(mac.Mac)
    unknown_key = new_key(MAC_TEMPLATE, key_id=1)
    self.assertEqual(primitive_set.primitive(unknown_key), [])

  def test_primitive_from_identifier_returns_entry(self):
    primitive_set = core.new_primitive_set(mac.Mac)
    key = new_key(MAC_TEMPLATE, key_id=1)
    primitive = core.Registry.primitive(key.key_data, mac.Mac)
    primitive_set.add_primitive(primitive, key)

    ident = core.crypto_format.output_prefix(key)
    entries = primitive_set.primitive_from_identifier(ident)
    self.assertLen(entries, 1)
    entry = entries[0]
    self.assertEqual(primitive, entry.primitive)
    self.assertEqual(tink_pb2.ENABLED, entry.status)
    self.assertEqual(ident, entry.identifier)
    self.assertEqual(1, entry.key_id)

  def test_list_of_entries_can_be_modified(self):
    primitive_set = core.new_primitive_set(mac.Mac)
    key = new_key(MAC_TEMPLATE, key_id=1)
    primitive = core.Registry.primitive(key.key_data, mac.Mac)
    primitive_set.add_primitive(primitive, key)
    entries = primitive_set.primitive(key)
    entries.append('Something')
    self.assertLen(primitive_set.primitive(key), 1)

  def test_primary_returns_primary(self):
    primitive_set = core.new_primitive_set(mac.Mac)
    key = new_key(MAC_TEMPLATE, key_id=1)
    primitive = core.Registry.primitive(key.key_data, mac.Mac)
    entry = primitive_set.add_primitive(primitive, key)
    primitive_set.set_primary(entry)

    entry = primitive_set.primary()
    self.assertEqual(primitive, entry.primitive)
    self.assertEqual(tink_pb2.ENABLED, entry.status)
    self.assertEqual(core.crypto_format.output_prefix(key), entry.identifier)
    self.assertEqual(1, entry.key_id)

  def test_primary_returns_none(self):
    primitive_set = core.new_primitive_set(mac.Mac)
    key = new_key(MAC_TEMPLATE, key_id=1)
    primitive = core.Registry.primitive(key.key_data, mac.Mac)
    primitive_set.add_primitive(primitive, key)
    self.assertIsNone(primitive_set.primary())

  def test_same_key_id_and_prefix_type(self):
    primitive_set = core.new_primitive_set(mac.Mac)
    key1 = new_key(MAC_TEMPLATE, key_id=1)
    primitive1 = core.Registry.primitive(key1.key_data, mac.Mac)
    primitive_set.add_primitive(primitive1, key1)
    key2 = new_key(MAC_TEMPLATE, key_id=1, status=tink_pb2.DISABLED)
    primitive2 = core.Registry.primitive(key2.key_data, mac.Mac)
    primitive_set.add_primitive(primitive2, key2)

    expected_ident = core.crypto_format.output_prefix(key1)
    entries = primitive_set.primitive(key1)
    self.assertLen(entries, 2)
    self.assertEqual(primitive1, entries[0].primitive)
    self.assertEqual(primitive2, entries[1].primitive)
    self.assertEqual(tink_pb2.ENABLED, entries[0].status)
    self.assertEqual(tink_pb2.DISABLED, entries[1].status)
    self.assertEqual(expected_ident, entries[0].identifier)
    self.assertEqual(expected_ident, entries[1].identifier)
    self.assertEqual(1, entries[0].key_id)
    self.assertEqual(1, entries[1].key_id)
    self.assertLen(primitive_set.primitive(key2), 2)

  def test_same_key_id_but_different_prefix_type(self):
    primitive_set = core.new_primitive_set(mac.Mac)
    key1 = new_key(MAC_TEMPLATE, key_id=1, output_prefix_type=tink_pb2.TINK)
    primitive1 = core.Registry.primitive(key1.key_data, mac.Mac)
    primitive_set.add_primitive(primitive1, key1)
    key2 = new_key(MAC_TEMPLATE, key_id=1, output_prefix_type=tink_pb2.LEGACY)
    primitive2 = core.Registry.primitive(key2.key_data, mac.Mac)
    primitive_set.add_primitive(primitive2, key2)

    entries1 = primitive_set.primitive(key1)
    self.assertLen(entries1, 1)
    self.assertEqual(primitive1, entries1[0].primitive)
    self.assertEqual(tink_pb2.ENABLED, entries1[0].status)
    self.assertEqual(core.crypto_format.output_prefix(key1),
                     entries1[0].identifier)
    self.assertEqual(1, entries1[0].key_id)

    entries2 = primitive_set.primitive(key2)
    self.assertLen(entries2, 1)
    self.assertEqual(primitive2, entries2[0].primitive)
    self.assertEqual(tink_pb2.ENABLED, entries2[0].status)
    self.assertEqual(core.crypto_format.output_prefix(key2),
                     entries2[0].identifier)
    self.assertEqual(1, entries2[0].key_id)

  def test_add_invalid_key_fails(self):
    primitive_set = core.new_primitive_set(mac.Mac)
    key = new_key(MAC_TEMPLATE, key_id=1)
    key.ClearField('output_prefix_type')
    with self.assertRaises(core.TinkError):
      primitive_set.add_primitive(helper.FakeMac(), key)

  def test_add_wrong_primitive_fails(self):
    primitive_set = core.new_primitive_set(aead.Aead)
    key = new_key(MAC_TEMPLATE, key_id=1, output_prefix_type=tink_pb2.TINK)
    primitive = core.Registry.primitive(key.key_data, mac.Mac)
    with self.assertRaises(core.TinkError):
      primitive_set.add_primitive(primitive, key)

  def test_primitive_class(self):
    primitive_set = core.new_primitive_set(mac.Mac)
    self.assertEqual(primitive_set.primitive_class(), mac.Mac)

  def test_raw_primitives(self):
    primitive_set = core.new_primitive_set(mac.Mac)
    key1 = new_key(MAC_TEMPLATE, key_id=1, output_prefix_type=tink_pb2.TINK)
    primitive1 = core.Registry.primitive(key1.key_data, mac.Mac)
    primitive_set.add_primitive(primitive1, key1)
    key2 = new_key(MAC_TEMPLATE, key_id=1, output_prefix_type=tink_pb2.RAW)
    primitive2 = core.Registry.primitive(key2.key_data, mac.Mac)
    primitive_set.add_primitive(primitive2, key2)
    key3 = new_key(
        MAC_TEMPLATE,
        key_id=3,
        output_prefix_type=tink_pb2.RAW,
        status=tink_pb2.DISABLED)
    primitive3 = core.Registry.primitive(key3.key_data, mac.Mac)
    primitive_set.add_primitive(primitive3, key3)

    entries = primitive_set.raw_primitives()
    self.assertLen(entries, 2)
    self.assertEqual(primitive2, entries[0].primitive)
    self.assertEqual(tink_pb2.ENABLED, entries[0].status)
    self.assertEqual(core.crypto_format.RAW_PREFIX,
                     entries[0].identifier)
    self.assertEqual(1, entries[0].key_id)
    self.assertEqual(primitive3, entries[1].primitive)
    self.assertEqual(tink_pb2.DISABLED, entries[1].status)
    self.assertEqual(core.crypto_format.RAW_PREFIX,
                     entries[1].identifier)
    self.assertEqual(3, entries[1].key_id)

  def test_all_primitives(self):
    primitive_set = core.new_primitive_set(mac.Mac)

    key0 = new_key(MAC_TEMPLATE, key_id=88, output_prefix_type=tink_pb2.TINK)
    primitive0 = core.Registry.primitive(key0.key_data, mac.Mac)
    primitive_set.add_primitive(primitive0, key0)

    key1 = new_key(MAC_TEMPLATE, key_id=88, output_prefix_type=tink_pb2.LEGACY)
    primitive1 = core.Registry.primitive(key1.key_data, mac.Mac)
    primitive_set.add_primitive(primitive1, key1)

    key2 = new_key(MAC_TEMPLATE, key_id=88, output_prefix_type=tink_pb2.RAW)
    primitive2 = core.Registry.primitive(key2.key_data, mac.Mac)
    primitive_set.add_primitive(primitive2, key2)

    key3 = new_key(
        MAC_TEMPLATE,
        key_id=89,
        output_prefix_type=tink_pb2.RAW,
        status=tink_pb2.DISABLED)
    primitive3 = core.Registry.primitive(key3.key_data, mac.Mac)
    primitive_set.add_primitive(primitive3, key3)

    key4 = new_key(MAC_TEMPLATE, key_id=88, output_prefix_type=tink_pb2.TINK)
    primitive0 = core.Registry.primitive(key4.key_data, mac.Mac)
    primitive_set.add_primitive(primitive0, key4)

    list_of_entries = primitive_set.all()

    v = []
    for entries in list_of_entries:
      v.append(
          sorted([
              (e.identifier, e.output_prefix_type, e.key_id) for e in entries
          ]))
    self.assertCountEqual(v, [
        [(b'', tink_pb2.RAW, 88), (b'', tink_pb2.RAW, 89)],
        [(b'\x01\x00\x00\x00X', tink_pb2.TINK, 88),
         (b'\x01\x00\x00\x00X', tink_pb2.TINK, 88)],
        [(b'\x00\x00\x00\x00X', tink_pb2.LEGACY, 88)],
    ])

if __name__ == '__main__':
  absltest.main()
