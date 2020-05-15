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
"""Tests for tink.tools.testing.cross_language.util.cli_aead."""

from absl.testing import absltest
from absl.testing import parameterized
import tink
from tink import aead
from tools.testing.cross_language.util import cli_aead


def setUpModule():
  aead.register()


class CliAeadTest(parameterized.TestCase):

  @parameterized.parameters(*cli_aead.LANGUAGES)
  def test_encrypt_decrypt_success(self, lang):
    keyset_handle = tink.new_keyset_handle(
        aead.aead_key_templates.AES128_GCM)
    primitive = cli_aead.CliAead(lang, keyset_handle)
    plaintext = b'plaintext'
    associated_data = b'associated_data'
    ciphertext = primitive.encrypt(plaintext, associated_data)
    output = primitive.decrypt(ciphertext, associated_data)
    self.assertEqual(output, plaintext)

  @parameterized.parameters(*cli_aead.LANGUAGES)
  def test_invalid_decrypt_raises_error(self, lang):
    keyset_handle = tink.new_keyset_handle(
        aead.aead_key_templates.AES128_GCM)
    primitive = cli_aead.CliAead(lang, keyset_handle)
    with self.assertRaises(tink.TinkError):
      primitive.decrypt(b'invalid ciphertext', b'associated_data')


if __name__ == '__main__':
  absltest.main()
