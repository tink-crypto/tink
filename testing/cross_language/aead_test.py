# Copyright 2020 Google LLC
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
"""Cross-language tests for the Aead primitive.

These tests check some basic AEAD properties, and that all implementations can
interoperate with each other.
"""

# Placeholder for import for type annotations
from typing import Iterable, Text, Tuple

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import aead

from tink.proto import tink_pb2
from tink.testing import keyset_builder
from util import supported_key_types
from util import testing_servers

SUPPORTED_LANGUAGES = testing_servers.SUPPORTED_LANGUAGES_BY_PRIMITIVE['aead']


def setUpModule():
  aead.register()
  testing_servers.start('aead')


def tearDownModule():
  testing_servers.stop()


# To test all implementations of AEAD, we simply try all availalble default key
# templates.
# Note that in order to test keys not covered by key templates, the parameter
# function would need to be rewritten to yield keyset instead of key template
# names.


def all_aead_key_template_names() -> Iterable[Text]:
  """Yields all AEAD key template names."""
  for key_type in supported_key_types.AEAD_KEY_TYPES:
    for key_template_name in supported_key_types.KEY_TEMPLATE_NAMES[key_type]:
      yield key_template_name


class AeadPythonTest(parameterized.TestCase):

  @parameterized.parameters(all_aead_key_template_names())
  def test_encrypt_decrypt(self, key_template_name):
    supported_langs = supported_key_types.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[
        key_template_name]
    self.assertNotEmpty(supported_langs)
    key_template = supported_key_types.KEY_TEMPLATE[key_template_name]
    # Take the first supported language to generate the keyset.
    keyset = testing_servers.new_keyset(supported_langs[0], key_template)
    supported_aeads = [
        testing_servers.aead(lang, keyset) for lang in supported_langs
    ]
    unsupported_aeads = [
        testing_servers.aead(lang, keyset)
        for lang in SUPPORTED_LANGUAGES
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
        with self.assertRaises(
            tink.TinkError,
            msg='Language %s supports AEAD decrypt with %s unexpectedly' %
            (p2.lang, key_template_name)):
          p2.decrypt(ciphertext, associated_data)
    for p in unsupported_aeads:
      with self.assertRaises(
          tink.TinkError,
          msg='Language %s supports AEAD encrypt with %s unexpectedly' % (
              p.lang, key_template_name)):
        p.encrypt(b'plaintext', b'associated_data')


# If the implementations work fine for keysets with single keys, then key
# rotation should work if the primitive wrapper is implemented correctly.
# These wrappers do not depend on the key type, so it should be fine to always
# test with the same key type. Since the AEAD wrapper needs to treat keys
# with output prefix RAW differently, we also include such a template for that.
KEY_ROTATION_TEMPLATES = [
    aead.aead_key_templates.AES128_CTR_HMAC_SHA256,
    keyset_builder.raw_template(aead.aead_key_templates.AES128_CTR_HMAC_SHA256)
]


def key_rotation_test_cases(
) -> Iterable[Tuple[Text, Text, tink_pb2.KeyTemplate, tink_pb2.KeyTemplate]]:
  for enc_lang in SUPPORTED_LANGUAGES:
    for dec_lang in SUPPORTED_LANGUAGES:
      for old_key_tmpl in KEY_ROTATION_TEMPLATES:
        for new_key_tmpl in KEY_ROTATION_TEMPLATES:
          yield (enc_lang, dec_lang, old_key_tmpl, new_key_tmpl)


class AeadKeyRotationTest(parameterized.TestCase):

  @parameterized.parameters(key_rotation_test_cases())
  def test_key_rotation(self, enc_lang, dec_lang, old_key_tmpl, new_key_tmpl):
    # Do a key rotation from an old key generated from old_key_tmpl to a new
    # key generated from new_key_tmpl. Encryption and decryption are done
    # in languages enc_lang and dec_lang.
    builder = keyset_builder.new_keyset_builder()
    older_key_id = builder.add_new_key(old_key_tmpl)
    builder.set_primary_key(older_key_id)
    enc_aead1 = testing_servers.aead(enc_lang, builder.keyset())
    dec_aead1 = testing_servers.aead(dec_lang, builder.keyset())
    newer_key_id = builder.add_new_key(new_key_tmpl)
    enc_aead2 = testing_servers.aead(enc_lang, builder.keyset())
    dec_aead2 = testing_servers.aead(dec_lang, builder.keyset())

    builder.set_primary_key(newer_key_id)
    enc_aead3 = testing_servers.aead(enc_lang, builder.keyset())
    dec_aead3 = testing_servers.aead(dec_lang, builder.keyset())

    builder.disable_key(older_key_id)
    enc_aead4 = testing_servers.aead(enc_lang, builder.keyset())
    dec_aead4 = testing_servers.aead(dec_lang, builder.keyset())

    self.assertNotEqual(older_key_id, newer_key_id)
    # 1 encrypts with the older key. So 1, 2 and 3 can decrypt it, but not 4.
    ciphertext1 = enc_aead1.encrypt(b'plaintext', b'ad')
    self.assertEqual(dec_aead1.decrypt(ciphertext1, b'ad'), b'plaintext')
    self.assertEqual(dec_aead2.decrypt(ciphertext1, b'ad'), b'plaintext')
    self.assertEqual(dec_aead3.decrypt(ciphertext1, b'ad'), b'plaintext')
    with self.assertRaises(tink.TinkError):
      _ = dec_aead4.decrypt(ciphertext1, b'ad')

    # 2 encrypts with the older key. So 1, 2 and 3 can decrypt it, but not 4.
    ciphertext2 = enc_aead2.encrypt(b'plaintext', b'ad')
    self.assertEqual(dec_aead1.decrypt(ciphertext2, b'ad'), b'plaintext')
    self.assertEqual(dec_aead2.decrypt(ciphertext2, b'ad'), b'plaintext')
    self.assertEqual(dec_aead3.decrypt(ciphertext2, b'ad'), b'plaintext')
    with self.assertRaises(tink.TinkError):
      _ = dec_aead4.decrypt(ciphertext2, b'ad')

    # 3 encrypts with the newer key. So 2, 3 and 4 can decrypt it, but not 1.
    ciphertext3 = enc_aead3.encrypt(b'plaintext', b'ad')
    with self.assertRaises(tink.TinkError):
      _ = dec_aead1.decrypt(ciphertext3, b'ad')
    self.assertEqual(dec_aead2.decrypt(ciphertext3, b'ad'), b'plaintext')
    self.assertEqual(dec_aead3.decrypt(ciphertext3, b'ad'), b'plaintext')
    self.assertEqual(dec_aead4.decrypt(ciphertext3, b'ad'), b'plaintext')

    # 4 encrypts with the newer key. So 2, 3 and 4 can decrypt it, but not 1.
    ciphertext4 = enc_aead4.encrypt(b'plaintext', b'ad')
    with self.assertRaises(tink.TinkError):
      _ = dec_aead1.decrypt(ciphertext4, b'ad')
    self.assertEqual(dec_aead2.decrypt(ciphertext4, b'ad'), b'plaintext')
    self.assertEqual(dec_aead3.decrypt(ciphertext4, b'ad'), b'plaintext')
    self.assertEqual(dec_aead4.decrypt(ciphertext4, b'ad'), b'plaintext')

if __name__ == '__main__':
  absltest.main()
