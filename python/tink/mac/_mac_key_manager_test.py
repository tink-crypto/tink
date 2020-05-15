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

from tink.proto import common_pb2
from tink.proto import hmac_pb2
from tink.proto import tink_pb2

from tink import core
from tink import mac


def setUpModule():
  mac.register()


class MacKeyManagerTest(absltest.TestCase):

  def setUp(self):
    super(MacKeyManagerTest, self).setUp()
    self.key_manager = core.Registry.key_manager(
        'type.googleapis.com/google.crypto.tink.HmacKey')

  def new_hmac_key_template(self, hash_type, tag_size, key_size):
    key_format = hmac_pb2.HmacKeyFormat()
    key_format.params.hash = hash_type
    key_format.params.tag_size = tag_size
    key_format.key_size = key_size
    key_template = tink_pb2.KeyTemplate()
    key_template.type_url = ('type.googleapis.com/google.crypto.tink.HmacKey')
    key_template.value = key_format.SerializeToString()
    return key_template

  def test_primitive_class(self):
    self.assertEqual(self.key_manager.primitive_class(), mac.Mac)

  def test_key_type(self):
    self.assertEqual(self.key_manager.key_type(),
                     'type.googleapis.com/google.crypto.tink.HmacKey')

  def test_new_key_data(self):
    key_template = self.new_hmac_key_template(common_pb2.SHA256, 24, 16)
    key_data = self.key_manager.new_key_data(key_template)
    self.assertEqual(key_data.type_url, self.key_manager.key_type())
    key = hmac_pb2.HmacKey()
    key.ParseFromString(key_data.value)
    self.assertEqual(key.version, 0)
    self.assertEqual(key.params.hash, common_pb2.SHA256)
    self.assertEqual(key.params.tag_size, 24)
    self.assertLen(key.key_value, 16)

  def test_invalid_params_throw_exception(self):
    key_template = self.new_hmac_key_template(common_pb2.SHA256, 9, 16)
    with self.assertRaisesRegex(core.TinkError, 'Invalid HmacParams'):
      self.key_manager.new_key_data(key_template)

  def test_mac_success(self):
    mac_primitive = self.key_manager.primitive(
        self.key_manager.new_key_data(
            self.new_hmac_key_template(common_pb2.SHA256, 24, 16)))
    data = b'data'
    tag = mac_primitive.compute_mac(data)
    self.assertLen(tag, 24)
    # No exception raised, no return value.
    self.assertIsNone(mac_primitive.verify_mac(tag, data))

  def test_mac_wrong(self):
    mac_primitive = self.key_manager.primitive(
        self.key_manager.new_key_data(
            self.new_hmac_key_template(common_pb2.SHA256, 16, 16)))
    with self.assertRaisesRegex(core.TinkError, 'verification failed'):
      mac_primitive.verify_mac(b'0123456789ABCDEF', b'data')


if __name__ == '__main__':
  absltest.main()
