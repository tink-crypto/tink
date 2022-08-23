# Copyright 2022 Google LLC
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
"""Cross-language tests for the KMS Envelope AEAD primitive with AWS and GCP."""

from typing import Dict, Iterable

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import aead

from tink.proto import tink_pb2
from util import supported_key_types
from util import testing_servers

_GCP_KEY_URI = ('gcp-kms://projects/tink-test-infrastructure/locations/global/'
                'keyRings/unit-and-integration-testing/cryptoKeys/aead-key')


def _templates() -> Dict[str, tuple[tink_pb2.KeyTemplate, str]]:
  """For each KMS envelope AEAD template name maps the key template and DEK AEAD key type."""
  kms_key_templates = {}
  for aead_key_type in supported_key_types.AEAD_KEY_TYPES:
    for key_template_name in supported_key_types.KEY_TEMPLATE_NAMES[
        aead_key_type]:
      envelope_aead_key_template = (
          aead.aead_key_templates.create_kms_envelope_aead_key_template(
              _GCP_KEY_URI,
              supported_key_types.KEY_TEMPLATE[key_template_name]))
      kms_key_templates['GCP_KMS_ENVELOPE_AEAD_WITH_%s' %
                        key_template_name] = (envelope_aead_key_template,
                                              aead_key_type)
  return kms_key_templates


_KMS_KEY_TEMPLATES = _templates()
_SUPPORTED_LANGUAGES_FOR_KMS_ENVELOPE_AEAD = ('python', 'cc', 'go', 'java')


def setUpModule():
  aead.register()
  testing_servers.start('aead')


def tearDownModule():
  testing_servers.stop()


def _test_cases() -> Iterable[str]:
  """Yields (KMS Envelope AEAD template names, encrypt lang, decrypt lang)."""
  for key_template_name, (_, aead_key_type) in _KMS_KEY_TEMPLATES.items():
    # Make sure to test languages that support the pritive used for DEK.
    supported_langs = supported_key_types.SUPPORTED_LANGUAGES[aead_key_type]
    # Make sure the language supports KMS envelope encryption.
    supported_langs = set(supported_langs).intersection(
        _SUPPORTED_LANGUAGES_FOR_KMS_ENVELOPE_AEAD)
    for encrypt_lang in supported_langs:
      for decrypt_lang in supported_langs:
        yield (key_template_name, encrypt_lang, decrypt_lang)


def _get_plaintext_and_aad(key_template_name: str,
                           lang: str) -> tuple[bytes, bytes]:
  """Creates test plaintext and associated data from a key template and lang."""
  plaintext = (
      b'This is some plaintext message to be encrypted using key_template '
      b'%s using %s for encryption.' %
      (key_template_name.encode('utf8'), lang.encode('utf8')))
  associated_data = (b'Some associated data for %s using %s for encryption.' %
                     (key_template_name.encode('utf8'), lang.encode('utf8')))
  return (plaintext, associated_data)


class KmsEnvelopeAeadTest(parameterized.TestCase):

  @parameterized.parameters(_test_cases())
  def test_encrypt_decrypt(self, key_template_name, encrypt_lang, decrypt_lang):
    key_template, _ = _KMS_KEY_TEMPLATES[key_template_name]
    # Use the encryption language to generate the keyset proto.
    keyset = testing_servers.new_keyset(encrypt_lang, key_template)
    encrypt_primitive = testing_servers.aead(encrypt_lang, keyset)
    plaintext, associated_data = _get_plaintext_and_aad(key_template_name,
                                                        encrypt_primitive.lang)
    ciphertext = encrypt_primitive.encrypt(plaintext, associated_data)

    # Decrypt.
    decrypt_primitive = testing_servers.aead(decrypt_lang, keyset)
    output = decrypt_primitive.decrypt(ciphertext, associated_data)
    self.assertEqual(output, plaintext)

  @parameterized.parameters(_test_cases())
  def test_decryption_fails_with_wrong_aad(self, key_template_name,
                                           encrypt_lang, decrypt_lang):
    key_template, _ = _KMS_KEY_TEMPLATES[key_template_name]
    # Use the encryption language to generate the keyset proto.
    keyset = testing_servers.new_keyset(encrypt_lang, key_template)
    encrypt_primitive = testing_servers.aead(encrypt_lang, keyset)
    plaintext, associated_data = _get_plaintext_and_aad(key_template_name,
                                                        encrypt_primitive.lang)
    ciphertext = encrypt_primitive.encrypt(plaintext, associated_data)
    decrypt_primitive = testing_servers.aead(decrypt_lang, keyset)
    with self.assertRaises(tink.TinkError, msg='decryption failed'):
      decrypt_primitive.decrypt(ciphertext, b'wrong aad')


# TODO(b/242686943): That that two different key ids can't decrypt each other.

if __name__ == '__main__':
  absltest.main()
