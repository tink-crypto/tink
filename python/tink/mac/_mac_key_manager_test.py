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
"""Tests for tink.python.tink._mac_key_manager."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from absl.testing import absltest
from absl.testing import parameterized

from tink.proto import common_pb2
from tink.proto import hmac_pb2

import tink
from tink import core
from tink import mac


def setUpModule():
  mac.register()


class MacKeyManagerTest(parameterized.TestCase):

  def test_new_key_data_hmac(self):
    key_template = mac.mac_key_templates.create_hmac_key_template(
        key_size=16, tag_size=24, hash_type=common_pb2.SHA256)
    key_manager = core.Registry.key_manager(key_template.type_url)
    key_data = key_manager.new_key_data(key_template)
    self.assertEqual(key_data.type_url, key_manager.key_type())
    key = hmac_pb2.HmacKey()
    key.ParseFromString(key_data.value)
    self.assertEqual(key.version, 0)
    self.assertEqual(key.params.hash, common_pb2.SHA256)
    self.assertEqual(key.params.tag_size, 24)
    self.assertLen(key.key_value, 16)

  def test_invalid_params_throw_exception(self):
    key_template = mac.mac_key_templates.create_hmac_key_template(
        key_size=16, tag_size=9, hash_type=common_pb2.SHA256)
    with self.assertRaises(core.TinkError):
      tink.new_keyset_handle(key_template)

  @parameterized.parameters([
      mac.mac_key_templates.HMAC_SHA256_128BITTAG,
      mac.mac_key_templates.HMAC_SHA256_256BITTAG,
      mac.mac_key_templates.HMAC_SHA512_256BITTAG,
      mac.mac_key_templates.HMAC_SHA512_512BITTAG,
  ])
  def test_mac_success(self, key_template):
    keyset_handle = tink.new_keyset_handle(key_template)
    mac_primitive = keyset_handle.primitive(mac.Mac)
    data = b'data'
    tag = mac_primitive.compute_mac(data)
    self.assertGreaterEqual(len(tag), 16)
    # No exception raised, no return value.
    self.assertIsNone(mac_primitive.verify_mac(tag, data))

  @parameterized.parameters([
      mac.mac_key_templates.HMAC_SHA256_128BITTAG,
      mac.mac_key_templates.HMAC_SHA256_256BITTAG,
      mac.mac_key_templates.HMAC_SHA512_256BITTAG,
      mac.mac_key_templates.HMAC_SHA512_512BITTAG,
  ])
  def test_mac_wrong(self, key_template):
    keyset_handle = tink.new_keyset_handle(key_template)
    mac_primitive = keyset_handle.primitive(mac.Mac)
    with self.assertRaises(core.TinkError):
      mac_primitive.verify_mac(b'0123456789ABCDEF', b'data')


if __name__ == '__main__':
  absltest.main()
