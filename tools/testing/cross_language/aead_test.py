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
"""Cross-language tests for the Aead primitive."""

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import aead

from tools.testing import supported_key_types
from tools.testing.cross_language.util import cli_aead
from tools.testing.cross_language.util import keyset_builder


def setUpModule():
  aead.register()


class AeadPythonTest(parameterized.TestCase):

  @parameterized.parameters(
      supported_key_types.test_cases(supported_key_types.AEAD_KEY_TYPES))
  def test_encrypt_decrypt(self, key_template_name, supported_langs):
    key_template = supported_key_types.KEY_TEMPLATE[key_template_name]
    keyset_handle = keyset_builder.new_keyset_handle(key_template)
    supported_aeads = [
        cli_aead.CliAead(lang, keyset_handle) for lang in supported_langs
    ]
    unsupported_aeads = [
        cli_aead.CliAead(lang, keyset_handle)
        for lang in cli_aead.LANGUAGES
        if lang not in supported_langs
    ]
    for p in supported_aeads:
      plaintext = (
          b'This is some plaintext message to be encrypted using key_template '
          b'%s using %s for encryption.'
          % (key_template_name.encode('utf8'), p.lang.encode('utf8')))
      associated_data = (
          b'Some associated data for %s using %s for encryption.' %
          (key_template_name.encode('utf8'), p.lang.encode('utf8')))
      ciphertext = p.encrypt(plaintext, associated_data)
      for p2 in supported_aeads:
        output = p2.decrypt(ciphertext, associated_data)
        self.assertEqual(output, plaintext)
      for p2 in unsupported_aeads:
        with self.assertRaises(tink.TinkError):
          p2.decrypt(ciphertext, associated_data)
    for p in unsupported_aeads:
      with self.assertRaises(tink.TinkError):
        p.encrypt(b'plaintext', b'associated_data')

if __name__ == '__main__':
  absltest.main()
