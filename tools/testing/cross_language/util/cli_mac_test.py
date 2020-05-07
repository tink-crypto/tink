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
"""Tests for tink.tools.testing.cross_language.util.cli_mac."""

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import mac

from tools.testing.cross_language.util import cli_mac


def setUpModule():
  mac.register()


class MacCliWrapperTest(parameterized.TestCase):

  @parameterized.parameters(*cli_mac.LANGUAGES)
  def test_mac_success(self, lang):
    keyset_handle = tink.new_keyset_handle(
        mac.mac_key_templates.HMAC_SHA256_128BITTAG)
    mac_primitive = cli_mac.CliMac(lang, keyset_handle)
    data = b'data'
    mac_value = mac_primitive.compute_mac(data)
    self.assertIsNone(mac_primitive.verify_mac(mac_value, data))

  @parameterized.parameters(*cli_mac.LANGUAGES)
  def test_mac_wrong(self, lang):
    keyset_handle = tink.new_keyset_handle(
        mac.mac_key_templates.HMAC_SHA256_128BITTAG)
    mac_primitive = cli_mac.CliMac(lang, keyset_handle)
    with self.assertRaisesRegex(tink.TinkError, 'verification failed'):
      mac_primitive.verify_mac(b'0123456789ABCDEF', b'data')


if __name__ == '__main__':
  absltest.main()
