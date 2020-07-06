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

from util import supported_key_types
from util import testing_servers

SUPPORTED_LANGUAGES = testing_servers.SUPPORTED_LANGUAGES_BY_PRIMITIVE['mac']


def setUpModule():
  mac.register()
  testing_servers.start()


def tearDownModule():
  testing_servers.stop()


class MacTest(parameterized.TestCase):

  @parameterized.parameters(
      supported_key_types.test_cases(supported_key_types.MAC_KEY_TYPES))
  def test_encrypt_decrypt(self, key_template_name, supported_langs):
    key_template = supported_key_types.KEY_TEMPLATE[key_template_name]
    keyset = testing_servers.new_keyset('java', key_template)
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


if __name__ == '__main__':
  absltest.main()
