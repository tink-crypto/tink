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
"""Cross-language tests for the StreamingAead primitive."""

import io

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import streaming_aead

from util import supported_key_types
from util import testing_servers

SUPPORTED_LANGUAGES = (testing_servers
                       .SUPPORTED_LANGUAGES_BY_PRIMITIVE['streaming_aead'])


def setUpModule():
  streaming_aead.register()
  testing_servers.start()


def tearDownModule():
  testing_servers.stop()


class StreamingAeadPythonTest(parameterized.TestCase):

  @parameterized.parameters(
      supported_key_types.test_cases(
          supported_key_types.STREAMING_AEAD_KEY_TYPES))
  def test_encrypt_decrypt(self, key_template_name, supported_langs):
    self.assertNotEmpty(supported_langs)
    key_template = supported_key_types.KEY_TEMPLATE[key_template_name]
    # Take the first supported language to generate the keyset.
    keyset = testing_servers.new_keyset(supported_langs[0], key_template)
    supported_streaming_aeads = [
        testing_servers.streaming_aead(lang, keyset) for lang in supported_langs
    ]
    unsupported_streaming_aeads = [
        testing_servers.streaming_aead(lang, keyset)
        for lang in SUPPORTED_LANGUAGES
        if lang not in supported_langs
    ]
    for p in supported_streaming_aeads:
      plaintext = (
          b'This is some plaintext message to be encrypted using key_template '
          b'%s using %s for encryption.'
          % (key_template_name.encode('utf8'), p.lang.encode('utf8')))
      associated_data = (
          b'Some associated data for %s using %s for encryption.' %
          (key_template_name.encode('utf8'), p.lang.encode('utf8')))
      plaintext_stream = io.BytesIO(plaintext)
      ciphertext_result_stream = p.new_encrypting_stream(
          plaintext_stream, associated_data)
      ciphertext = ciphertext_result_stream.read()
      for p2 in supported_streaming_aeads:
        ciphertext_stream = io.BytesIO(ciphertext)
        decrypted_stream = p2.new_decrypting_stream(
            ciphertext_stream, associated_data)
        self.assertEqual(decrypted_stream.read(), plaintext)
      for p2 in unsupported_streaming_aeads:
        with self.assertRaises(tink.TinkError):
          ciphertext_stream = io.BytesIO(ciphertext)
          decrypted_stream = p2.new_decrypting_stream(
              ciphertext_stream, associated_data)
    for p in unsupported_streaming_aeads:
      with self.assertRaises(tink.TinkError):
        plaintext_stream = io.BytesIO(b'plaintext')
        ciphertext_result_stream = p.new_encrypting_stream(
            plaintext_stream, b'associated_data')

if __name__ == '__main__':
  absltest.main()
