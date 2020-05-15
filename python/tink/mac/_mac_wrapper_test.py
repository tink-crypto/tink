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
"""Tests for tink.python.tink._mac_wrapper."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from absl.testing import absltest

from tink.proto import tink_pb2
from tink import core
from tink import mac
from tink.testing import helper


def setUpModule():
  mac.register()


class MacWrapperTest(absltest.TestCase):

  def new_primitive_key_pair(self, key_id, output_prefix_type):
    fake_key = helper.fake_key(
        key_id=key_id, output_prefix_type=output_prefix_type)
    fake_mac = helper.FakeMac('fakeMac {}'.format(key_id))
    return fake_mac, fake_key

  def test_verify_tink_mac(self):
    primitive, key = self.new_primitive_key_pair(1234, tink_pb2.TINK)
    pset = core.new_primitive_set(mac.Mac)
    pset.set_primary(pset.add_primitive(primitive, key))

    wrapped_mac = core.Registry.wrap(pset)
    tag = wrapped_mac.compute_mac(b'data')
    # No exception raised, no return value.
    self.assertIsNone(wrapped_mac.verify_mac(tag, b'data'))

  def test_verify_legacy_mac(self):
    primitive, key = self.new_primitive_key_pair(1234, tink_pb2.LEGACY)
    pset = core.new_primitive_set(mac.Mac)
    pset.set_primary(pset.add_primitive(primitive, key))

    wrapped_mac = core.Registry.wrap(pset)
    tag = wrapped_mac.compute_mac(b'data')
    # No exception raised, no return value.
    self.assertIsNone(wrapped_mac.verify_mac(tag, b'data'))

  def test_verify_macs_from_two_raw_keys(self):
    primitive1, raw_key1 = self.new_primitive_key_pair(1234, tink_pb2.RAW)
    primitive2, raw_key2 = self.new_primitive_key_pair(5678, tink_pb2.RAW)
    tag1 = primitive1.compute_mac(b'data1')
    tag2 = primitive2.compute_mac(b'data2')

    pset = core.new_primitive_set(mac.Mac)
    pset.add_primitive(primitive1, raw_key1)
    pset.set_primary(pset.add_primitive(primitive2, raw_key2))
    wrapped_mac = core.Registry.wrap(pset)

    self.assertIsNone(wrapped_mac.verify_mac(tag1, b'data1'))
    self.assertIsNone(wrapped_mac.verify_mac(tag2, b'data2'))
    self.assertIsNone(
        wrapped_mac.verify_mac(wrapped_mac.compute_mac(b'data'), b'data'))

  def test_verify_old_tink_mac_with_new_key(self):
    primitive, key = self.new_primitive_key_pair(1234, tink_pb2.TINK)
    pset = core.new_primitive_set(mac.Mac)
    pset.set_primary(pset.add_primitive(primitive, key))
    wrapped_mac = core.Registry.wrap(pset)
    tag = wrapped_mac.compute_mac(b'data')

    new_primitive, new_key = self.new_primitive_key_pair(5678, tink_pb2.TINK)
    pset.set_primary(pset.add_primitive(new_primitive, new_key))

    self.assertIsNone(wrapped_mac.verify_mac(tag, b'data'))

  def test_verify_old_raw_mac_with_new_key(self):
    primitive, key = self.new_primitive_key_pair(1234, tink_pb2.RAW)
    tag = primitive.compute_mac(b'data')

    pset = core.new_primitive_set(mac.Mac)
    pset.add_primitive(primitive, key)
    new_primitive, new_key = self.new_primitive_key_pair(5678, tink_pb2.TINK)
    pset.set_primary(pset.add_primitive(new_primitive, new_key))
    wrapped_mac = core.Registry.wrap(pset)
    self.assertIsNone(wrapped_mac.verify_mac(tag, b'data'))

  def test_verify_unknown_mac_fails(self):
    unknown_tag = helper.FakeMac('UnknownfakeMac').compute_mac(b'data')

    pset = core.new_primitive_set(mac.Mac)
    primitive, raw_key = self.new_primitive_key_pair(1234, tink_pb2.RAW)
    new_primitive, new_key = self.new_primitive_key_pair(5678, tink_pb2.TINK)
    pset.add_primitive(primitive, raw_key)
    new_entry = pset.add_primitive(new_primitive, new_key)
    pset.set_primary(new_entry)
    wrapped_mac = core.Registry.wrap(pset)

    with self.assertRaisesRegex(core.TinkError, 'invalid MAC'):
      wrapped_mac.verify_mac(unknown_tag, b'data')


if __name__ == '__main__':
  absltest.main()
