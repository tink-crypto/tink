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

from util import supported_key_types
from util import testing_servers


def setUpModule():
  aead.register()
  testing_servers.start()


def tearDownModule():
  testing_servers.stop()


class AeadPythonTest(parameterized.TestCase):

  @parameterized.parameters(
      supported_key_types.test_cases(supported_key_types.AEAD_KEY_TYPES))
  def test_encrypt_decrypt(self, key_template_name, supported_langs):
    key_template = supported_key_types.KEY_TEMPLATE[key_template_name]
    # use java to generate keys, as it supports all key types.
    keyset_handle = testing_servers.new_keyset_handle('java', key_template)
    supported_aeads = [
        testing_servers.aead(lang, keyset_handle) for lang in supported_langs
    ]
    unsupported_aeads = [
        testing_servers.aead(lang, keyset_handle)
        for lang in testing_servers.LANGUAGES
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
