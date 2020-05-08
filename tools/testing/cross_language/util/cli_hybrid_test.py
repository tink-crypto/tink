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
"""Tests for tink.tools.testing.cross_language.util.cli_hybrid."""

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import hybrid

from tools.testing.cross_language.util import cli_hybrid


def setUpModule():
  hybrid.register()


class CliHybridTest(parameterized.TestCase):

  @parameterized.parameters(*cli_hybrid.LANGUAGES)
  def test_encrypt_decrypt_success(self, lang):
    private_keyset_handle = tink.new_keyset_handle(
        hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM)
    public_keyset_handle = private_keyset_handle.public_keyset_handle()
    enc = cli_hybrid.CliHybridEncrypt(lang, public_keyset_handle)
    dec = cli_hybrid.CliHybridDecrypt(lang, private_keyset_handle)
    plaintext = b'plaintext'
    context_info = b'context_info'
    ciphertext = enc.encrypt(plaintext, context_info)
    output = dec.decrypt(ciphertext, context_info)
    self.assertEqual(output, plaintext)

  @parameterized.parameters(*cli_hybrid.LANGUAGES)
  def test_invalid_decrypt_raises_error(self, lang):
    private_keyset_handle = tink.new_keyset_handle(
        hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM)
    dec = cli_hybrid.CliHybridDecrypt(lang, private_keyset_handle)
    with self.assertRaises(tink.TinkError):
      dec.decrypt(b'invalid ciphertext', b'context_info')


if __name__ == '__main__':
  absltest.main()
