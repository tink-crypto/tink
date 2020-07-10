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
"""Cross-language tests for the MAC primitive."""

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import mac

from tink.proto import common_pb2
from tink.proto import tink_pb2
from util import keyset_builder
from util import supported_key_types
from util import testing_servers

SUPPORTED_LANGUAGES = testing_servers.SUPPORTED_LANGUAGES_BY_PRIMITIVE['mac']


def key_rotation_test_cases():
  for compute_lang in SUPPORTED_LANGUAGES:
    for verify_lang in SUPPORTED_LANGUAGES:
      for prefix in [tink_pb2.RAW, tink_pb2.TINK]:
        old_key_tmpl = mac.mac_key_templates.create_hmac_key_template(
            key_size=32, tag_size=16, hash_type=common_pb2.SHA256)
        old_key_tmpl.output_prefix_type = prefix
        new_key_tmpl = mac.mac_key_templates.HMAC_SHA512_512BITTAG
        yield (compute_lang, verify_lang, old_key_tmpl, new_key_tmpl)


def setUpModule():
  mac.register()
  testing_servers.start()


def tearDownModule():
  testing_servers.stop()


class MacTest(parameterized.TestCase):

  @parameterized.parameters(
      supported_key_types.test_cases(supported_key_types.MAC_KEY_TYPES))
  def test_encrypt_decrypt(self, key_template_name, supported_langs):
    self.assertNotEmpty(supported_langs)
    key_template = supported_key_types.KEY_TEMPLATE[key_template_name]
    # Take the first supported language to generate the keyset.
    keyset = testing_servers.new_keyset(supported_langs[0], key_template)
    supported_macs = [
        testing_servers.mac(lang, keyset) for lang in supported_langs
    ]
    unsupported_macs = [
        testing_servers.mac(lang, keyset)
        for lang in SUPPORTED_LANGUAGES
        if lang not in supported_langs
    ]
    for p in supported_macs:
      data = (
          b'This is some data to be authenticated using key_template '
          b'%s in %s.' % (key_template_name.encode('utf8'),
                          p.lang.encode('utf8')))
      mac_value = p.compute_mac(data)
      for p2 in supported_macs:
        self.assertIsNone(p2.verify_mac(mac_value, data))
      for p2 in unsupported_macs:
        with self.assertRaises(tink.TinkError):
          p2.verify_mac(mac_value, data)
    for p in unsupported_macs:
      with self.assertRaises(tink.TinkError):
        p.compute_mac(data)

  @parameterized.parameters(key_rotation_test_cases())
  def test_key_rotation(
      self, compute_lang, verify_lang, old_key_tmpl, new_key_tmpl):
    # Do a key rotation from an old key generated from old_key_tmpl to a new
    # key generated from new_key_tmpl. MAC computation and verification are done
    # in languages compute_lang and verify_lang.
    builder = keyset_builder.new_keyset_builder()
    older_key_id = builder.add_new_key(old_key_tmpl)
    builder.set_primary_key(older_key_id)
    compute_mac1 = testing_servers.mac(compute_lang, builder.keyset())
    verify_mac1 = testing_servers.mac(verify_lang, builder.keyset())
    newer_key_id = builder.add_new_key(new_key_tmpl)
    compute_mac2 = testing_servers.mac(compute_lang, builder.keyset())
    verify_mac2 = testing_servers.mac(verify_lang, builder.keyset())

    builder.set_primary_key(newer_key_id)
    compute_mac3 = testing_servers.mac(compute_lang, builder.keyset())
    verify_mac3 = testing_servers.mac(verify_lang, builder.keyset())

    builder.disable_key(older_key_id)
    compute_mac4 = testing_servers.mac(compute_lang, builder.keyset())
    verify_mac4 = testing_servers.mac(verify_lang, builder.keyset())

    self.assertNotEqual(older_key_id, newer_key_id)
    # 1 uses the older key. So 1, 2 and 3 can verify the mac, but not 4.
    mac_value1 = compute_mac1.compute_mac(b'plaintext')
    verify_mac1.verify_mac(mac_value1, b'plaintext')
    verify_mac2.verify_mac(mac_value1, b'plaintext')
    verify_mac3.verify_mac(mac_value1, b'plaintext')
    with self.assertRaises(tink.TinkError):
      verify_mac4.verify_mac(mac_value1, b'plaintext')

    # 2 uses the older key. So 1, 2 and 3 can verify the mac, but not 4.
    mac_value2 = compute_mac2.compute_mac(b'plaintext')
    verify_mac1.verify_mac(mac_value2, b'plaintext')
    verify_mac2.verify_mac(mac_value2, b'plaintext')
    verify_mac3.verify_mac(mac_value2, b'plaintext')
    with self.assertRaises(tink.TinkError):
      verify_mac4.verify_mac(mac_value2, b'plaintext')

    # 3 uses the newer key. So 2, 3 and 4 can verify the mac, but not 1.
    mac_value3 = compute_mac3.compute_mac(b'plaintext')
    with self.assertRaises(tink.TinkError):
      verify_mac1.verify_mac(mac_value3, b'plaintext')
    verify_mac2.verify_mac(mac_value3, b'plaintext')
    verify_mac3.verify_mac(mac_value3, b'plaintext')
    verify_mac4.verify_mac(mac_value3, b'plaintext')

    # 4 uses the newer key. So 2, 3 and 4 can verify the mac, but not 1.
    mac_value4 = compute_mac4.compute_mac(b'plaintext')
    with self.assertRaises(tink.TinkError):
      verify_mac1.verify_mac(mac_value4, b'plaintext')
    verify_mac2.verify_mac(mac_value4, b'plaintext')
    verify_mac3.verify_mac(mac_value4, b'plaintext')
    verify_mac4.verify_mac(mac_value4, b'plaintext')

if __name__ == '__main__':
  absltest.main()
