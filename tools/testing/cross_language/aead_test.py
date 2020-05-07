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
"""Tests for tink.tools.testing.python.cli."""

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import aead
from tools.testing.cross_language.util import cli_aead
from tools.testing.cross_language.util import cli_tinkey


def setUpModule():
  aead.register()


class AeadPythonTest(parameterized.TestCase):

  @parameterized.parameters(
      ('AES128_GCM', ('cc', 'go', 'java', 'python')),
      ('AES256_GCM', ('cc', 'go', 'java', 'python')),
      ('AES128_CTR_HMAC_SHA256', ('cc', 'go', 'java', 'python')),
      ('AES256_CTR_HMAC_SHA256', ('cc', 'go', 'java', 'python')),
      ('XCHACHA20_POLY1305', ('cc', 'go', 'java', 'python')),
      ('AES128_EAX', ('cc', 'java', 'python')),
      ('AES256_EAX', ('cc', 'java', 'python')),
      ('CHACHA20_POLY1305', ('go', 'java')))
  def test_encrypt_decrypt(self, key_template, supported_langs):
    keyset_handle = cli_tinkey.generate_keyset_handle(key_template)
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
          % (key_template.encode('utf8'), p.lang.encode('utf8')))
      associated_data = (
          b'Some associated data for %s using %s for encryption.' %
          (key_template.encode('utf8'), p.lang.encode('utf8')))
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
