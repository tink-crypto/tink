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
# Placeholder for import for type annotations
from __future__ import print_function

from absl.testing import absltest
from absl.testing import parameterized
import tink
from tink import mac
from tink.testing import keyset_builder


MAC_TEMPLATE = mac.mac_key_templates.HMAC_SHA256_128BITTAG
RAW_MAC_TEMPLATE = keyset_builder.raw_template(MAC_TEMPLATE)
LEGACY_MAC_TEMPLATE = keyset_builder.legacy_template(MAC_TEMPLATE)


def setUpModule():
  mac.register()


class MacWrapperTest(parameterized.TestCase):

  @parameterized.parameters([MAC_TEMPLATE,
                             RAW_MAC_TEMPLATE,
                             LEGACY_MAC_TEMPLATE])
  def test_compute_verify_mac(self, template):
    keyset_handle = tink.new_keyset_handle(template)
    primitive = keyset_handle.primitive(mac.Mac)
    tag = primitive.compute_mac(b'data')
    # No exception raised, no return value.
    self.assertIsNone(primitive.verify_mac(tag, b'data'))

  @parameterized.parameters([MAC_TEMPLATE,
                             RAW_MAC_TEMPLATE,
                             LEGACY_MAC_TEMPLATE])
  def test_verify_unknown_mac_fails(self, template):
    unknown_handle = tink.new_keyset_handle(template)
    unknown_primitive = unknown_handle.primitive(mac.Mac)
    unknown_tag = unknown_primitive.compute_mac(b'data')

    keyset_handle = tink.new_keyset_handle(template)
    primitive = keyset_handle.primitive(mac.Mac)
    with self.assertRaises(tink.TinkError):
      primitive.verify_mac(unknown_tag, b'data')

  @parameterized.parameters([MAC_TEMPLATE,
                             RAW_MAC_TEMPLATE,
                             LEGACY_MAC_TEMPLATE])
  def test_verify_short_mac_fails(self, template):
    keyset_handle = tink.new_keyset_handle(template)
    primitive = keyset_handle.primitive(mac.Mac)
    with self.assertRaises(tink.TinkError):
      primitive.verify_mac(b'', b'data')
    with self.assertRaises(tink.TinkError):
      primitive.verify_mac(b'tag', b'data')

  @parameterized.parameters(
      [(MAC_TEMPLATE, MAC_TEMPLATE),
       (MAC_TEMPLATE, RAW_MAC_TEMPLATE),
       (MAC_TEMPLATE, LEGACY_MAC_TEMPLATE),
       (RAW_MAC_TEMPLATE, MAC_TEMPLATE),
       (RAW_MAC_TEMPLATE, RAW_MAC_TEMPLATE),
       (RAW_MAC_TEMPLATE, LEGACY_MAC_TEMPLATE),
       (LEGACY_MAC_TEMPLATE, MAC_TEMPLATE),
       (LEGACY_MAC_TEMPLATE, RAW_MAC_TEMPLATE),
       (LEGACY_MAC_TEMPLATE, LEGACY_MAC_TEMPLATE)])
  def test_key_rotation(self, old_key_tmpl, new_key_tmpl):
    builder = keyset_builder.new_keyset_builder()
    older_key_id = builder.add_new_key(old_key_tmpl)

    builder.set_primary_key(older_key_id)
    mac1 = builder.keyset_handle().primitive(mac.Mac)

    newer_key_id = builder.add_new_key(new_key_tmpl)
    mac2 = builder.keyset_handle().primitive(mac.Mac)

    builder.set_primary_key(newer_key_id)
    mac3 = builder.keyset_handle().primitive(mac.Mac)

    builder.disable_key(older_key_id)
    mac4 = builder.keyset_handle().primitive(mac.Mac)

    self.assertNotEqual(older_key_id, newer_key_id)
    # 1 uses the older key. So 1, 2 and 3 can verify the mac, but not 4.
    mac_value1 = mac1.compute_mac(b'plaintext')
    mac1.verify_mac(mac_value1, b'plaintext')
    mac2.verify_mac(mac_value1, b'plaintext')
    mac3.verify_mac(mac_value1, b'plaintext')
    with self.assertRaises(tink.TinkError):
      mac4.verify_mac(mac_value1, b'plaintext')

    # 2 uses the older key. So 1, 2 and 3 can verify the mac, but not 4.
    mac_value2 = mac2.compute_mac(b'plaintext')
    mac1.verify_mac(mac_value2, b'plaintext')
    mac2.verify_mac(mac_value2, b'plaintext')
    mac3.verify_mac(mac_value2, b'plaintext')
    with self.assertRaises(tink.TinkError):
      mac4.verify_mac(mac_value2, b'plaintext')

    # 3 uses the newer key. So 2, 3 and 4 can verify the mac, but not 1.
    mac_value3 = mac3.compute_mac(b'plaintext')
    with self.assertRaises(tink.TinkError):
      mac1.verify_mac(mac_value3, b'plaintext')
    mac2.verify_mac(mac_value3, b'plaintext')
    mac3.verify_mac(mac_value3, b'plaintext')
    mac4.verify_mac(mac_value3, b'plaintext')

    # 4 uses the newer key. So 2, 3 and 4 can verify the mac, but not 1.
    mac_value4 = mac4.compute_mac(b'plaintext')
    with self.assertRaises(tink.TinkError):
      mac1.verify_mac(mac_value4, b'plaintext')
    mac2.verify_mac(mac_value4, b'plaintext')
    mac3.verify_mac(mac_value4, b'plaintext')
    mac4.verify_mac(mac_value4, b'plaintext')


if __name__ == '__main__':
  absltest.main()
