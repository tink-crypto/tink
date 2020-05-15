# Copyright 2019 Google LLC.
#
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
"""Tests for tink.tools.testing.cross_language.util.cli_signature."""

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import signature

from tools.testing.cross_language.util import cli_signature


def setUpModule():
  signature.register()


class CliSignatureTest(parameterized.TestCase):

  @parameterized.parameters(*cli_signature.LANGUAGES)
  def test_sign_verify_success(self, lang):
    private_keyset_handle = tink.new_keyset_handle(
        signature.signature_key_templates.ECDSA_P256)
    public_keyset_handle = private_keyset_handle.public_keyset_handle()
    signer = cli_signature.CliPublicKeySign(lang, private_keyset_handle)
    verifier = cli_signature.CliPublicKeyVerify(lang, public_keyset_handle)
    message = b'message'
    sign = signer.sign(message)
    self.assertIsNone(verifier.verify(sign, message))

  @parameterized.parameters(*cli_signature.LANGUAGES)
  def test_invalid_decrypt_raises_error(self, lang):
    private_keyset_handle = tink.new_keyset_handle(
        signature.signature_key_templates.ECDSA_P256)
    public_keyset_handle = private_keyset_handle.public_keyset_handle()
    verifier = cli_signature.CliPublicKeyVerify(lang, public_keyset_handle)
    with self.assertRaises(tink.TinkError):
      verifier.verify(b'invalid signature', b'message')


if __name__ == '__main__':
  absltest.main()
