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
"""Cross-language tests for Public-Key Signatures."""

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import signature

from util import supported_key_types
from util import testing_servers


def setUpModule():
  signature.register()
  testing_servers.start()


def tearDownModule():
  testing_servers.stop()


class SignaturePythonTest(parameterized.TestCase):

  @parameterized.parameters(
      supported_key_types.test_cases(supported_key_types.SIGNATURE_KEY_TYPES))
  def test_encrypt_decrypt(self, key_template_name, supported_langs):
    key_template = supported_key_types.KEY_TEMPLATE[key_template_name]
    private_handle = testing_servers.new_keyset_handle('java', key_template)
    supported_signers = [
        testing_servers.public_key_sign(lang, private_handle)
        for lang in supported_langs
    ]
    unsupported_signers = [
        testing_servers.public_key_sign(lang, private_handle)
        for lang in testing_servers.LANGUAGES
        if lang not in supported_langs
    ]
    public_handle = private_handle.public_keyset_handle()
    supported_verifiers = [
        testing_servers.public_key_verify(lang, public_handle)
        for lang in supported_langs
    ]
    unsupported_verifiers = [
        testing_servers.public_key_verify(lang, public_handle)
        for lang in testing_servers.LANGUAGES
        if lang not in supported_langs
    ]
    for signer in supported_signers:
      message = (
          b'A message to be signed using key_template %s in %s.'
          % (key_template_name.encode('utf8'), signer.lang.encode('utf8')))
      sign = signer.sign(message)
      for verifier in supported_verifiers:
        self.assertIsNone(verifier.verify(sign, message))
      for verifier in unsupported_verifiers:
        with self.assertRaises(tink.TinkError):
          verifier.verify(sign, message)
    for signer in unsupported_signers:
      with self.assertRaises(tink.TinkError):
        _ = signer.sign(message)


if __name__ == '__main__':
  absltest.main()
