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
"""Cross-language tests for Hybrid Encryption."""

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import hybrid

from util import supported_key_types
from util import testing_servers

SUPPORTED_LANGUAGES = testing_servers.SUPPORTED_LANGUAGES_BY_PRIMITIVE['hybrid']


def setUpModule():
  hybrid.register()
  testing_servers.start()


def tearDownModule():
  testing_servers.stop()


class HybridEncryptionTest(parameterized.TestCase):

  @parameterized.parameters(
      supported_key_types.test_cases(
          supported_key_types.HYBRID_PRIVATE_KEY_TYPES))
  def test_encrypt_decrypt(self, key_template_name, supported_langs):
    self.assertNotEmpty(supported_langs)
    key_template = supported_key_types.KEY_TEMPLATE[key_template_name]
    # Take the first supported language to generate the private keyset.
    private_keyset = testing_servers.new_keyset(supported_langs[0],
                                                key_template)
    supported_decs = [
        testing_servers.hybrid_decrypt(lang, private_keyset)
        for lang in supported_langs
    ]
    unsupported_decs = [
        testing_servers.hybrid_decrypt(lang, private_keyset)
        for lang in SUPPORTED_LANGUAGES
        if lang not in supported_langs
    ]
    public_keyset = testing_servers.public_keyset('java', private_keyset)
    supported_encs = [
        testing_servers.hybrid_encrypt(lang, public_keyset)
        for lang in supported_langs
    ]
    unsupported_encs = [
        testing_servers.hybrid_encrypt(lang, public_keyset)
        for lang in testing_servers.LANGUAGES
        if lang not in supported_langs
    ]
    for enc in supported_encs:
      plaintext = (
          b'This is some plaintext message to be encrypted using key_template '
          b'%s in %s.' % (key_template_name.encode('utf8'),
                          enc.lang.encode('utf8')))
      context_info = (
          b'Some context info for %s using %s for encryption.' %
          (key_template_name.encode('utf8'), enc.lang.encode('utf8')))
      ciphertext = enc.encrypt(plaintext, context_info)
      for dec in supported_decs:
        output = dec.decrypt(ciphertext, context_info)
        self.assertEqual(output, plaintext)
      for dec in unsupported_decs:
        with self.assertRaises(tink.TinkError):
          dec.decrypt(ciphertext, context_info)
    for enc in unsupported_encs:
      with self.assertRaises(tink.TinkError):
        enc.encrypt(b'plaintext', b'context_info')


if __name__ == '__main__':
  absltest.main()
