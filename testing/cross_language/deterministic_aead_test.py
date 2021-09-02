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
"""Cross-language tests for the DeterministicAead primitive."""

# Placeholder for import for type annotations
from typing import Iterable, Text

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import daead
from tink.testing import keyset_builder
from util import supported_key_types
from util import testing_servers

SUPPORTED_LANGUAGES = testing_servers.SUPPORTED_LANGUAGES_BY_PRIMITIVE['daead']


def setUpModule():
  daead.register()
  testing_servers.start('deterministic_aead')


def tearDownModule():
  testing_servers.stop()


def all_deterministic_aead_key_template_names() -> Iterable[Text]:
  """Yields all Deterministic AEAD key template names."""
  for key_type in supported_key_types.DAEAD_KEY_TYPES:
    for key_template_name in supported_key_types.KEY_TEMPLATE_NAMES[key_type]:
      yield key_template_name


class DeterministicAeadTest(parameterized.TestCase):

  @parameterized.parameters(all_deterministic_aead_key_template_names())
  def test_encrypt_decrypt(self, key_template_name):
    supported_langs = supported_key_types.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[
        key_template_name]
    self.assertNotEmpty(supported_langs)
    key_template = testing_servers.key_template('java', key_template_name)
    # Take the first supported language to generate the keyset.
    keyset = testing_servers.new_keyset(supported_langs[0], key_template)
    supported_daeads = [
        testing_servers.deterministic_aead(lang, keyset)
        for lang in supported_langs
    ]
    self.assertNotEmpty(supported_daeads)
    unsupported_daeads = [
        testing_servers.deterministic_aead(lang, keyset)
        for lang in SUPPORTED_LANGUAGES
        if lang not in supported_langs
    ]
    plaintext = (
        b'This is some plaintext message to be encrypted using '
        b'key_template %s.' % key_template_name.encode('utf8'))
    associated_data = (
        b'Some associated data for %s.' % key_template_name.encode('utf8'))
    ciphertext = None
    for p in supported_daeads:
      if ciphertext:
        self.assertEqual(
            ciphertext,
            p.encrypt_deterministically(plaintext, associated_data))
      else:
        ciphertext = p.encrypt_deterministically(plaintext, associated_data)
    for p2 in supported_daeads:
      output = p2.decrypt_deterministically(ciphertext, associated_data)
      self.assertEqual(output, plaintext)
    for p2 in unsupported_daeads:
      with self.assertRaises(
          tink.TinkError,
          msg='Language %s supports decrypt_deterministically with %s '
          'unexpectedly' % (p2.lang, key_template_name)):
        p2.decrypt_deterministically(ciphertext, associated_data)
    for p in unsupported_daeads:
      with self.assertRaises(
          tink.TinkError,
          msg='Language %s supports encrypt_deterministically with %s '
          'unexpectedly' % (p.lang, key_template_name)):
        p.encrypt_deterministically(b'plaintext', b'associated_data')


# If the implementations work fine for keysets with single keys, then key
# rotation should work if the primitive wrapper is implemented correctly.
# These wrappers do not depend on the key type, so it should be fine to always
# test with the same key type. But since the wrapper needs to treat keys
# with output prefix RAW differently, we also include such a template for that.
KEY_ROTATION_TEMPLATES = [
        daead.deterministic_aead_key_templates.AES256_SIV,
        keyset_builder.raw_template(
            daead.deterministic_aead_key_templates.AES256_SIV)
]


def key_rotation_test_cases():
  for enc_lang in SUPPORTED_LANGUAGES:
    for dec_lang in SUPPORTED_LANGUAGES:
      for old_key_tmpl in KEY_ROTATION_TEMPLATES:
        for new_key_tmpl in KEY_ROTATION_TEMPLATES:
          yield (enc_lang, dec_lang, old_key_tmpl, new_key_tmpl)


class DaeadKeyRotationTest(parameterized.TestCase):

  @parameterized.parameters(key_rotation_test_cases())
  def test_key_rotation(self, enc_lang, dec_lang, old_key_tmpl, new_key_tmpl):
    # Do a key rotation from an old key generated from old_key_tmpl to a new
    # key generated from new_key_tmpl. Encryption and decryption are done
    # in languages enc_lang and dec_lang.
    builder = keyset_builder.new_keyset_builder()
    older_key_id = builder.add_new_key(old_key_tmpl)
    builder.set_primary_key(older_key_id)
    enc_daead1 = testing_servers.deterministic_aead(enc_lang, builder.keyset())
    dec_daead1 = testing_servers.deterministic_aead(dec_lang, builder.keyset())
    newer_key_id = builder.add_new_key(new_key_tmpl)
    enc_daead2 = testing_servers.deterministic_aead(enc_lang, builder.keyset())
    dec_daead2 = testing_servers.deterministic_aead(dec_lang, builder.keyset())

    builder.set_primary_key(newer_key_id)
    enc_daead3 = testing_servers.deterministic_aead(enc_lang, builder.keyset())
    dec_daead3 = testing_servers.deterministic_aead(dec_lang, builder.keyset())

    builder.disable_key(older_key_id)
    enc_daead4 = testing_servers.deterministic_aead(enc_lang, builder.keyset())
    dec_daead4 = testing_servers.deterministic_aead(dec_lang, builder.keyset())

    self.assertNotEqual(older_key_id, newer_key_id)
    # 1 encrypts with the older key. So 1, 2 and 3 can decrypt it, but not 4.
    ciphertext1 = enc_daead1.encrypt_deterministically(b'plaintext', b'ad')
    self.assertEqual(dec_daead1.decrypt_deterministically(ciphertext1, b'ad'),
                     b'plaintext')
    self.assertEqual(dec_daead2.decrypt_deterministically(ciphertext1, b'ad'),
                     b'plaintext')
    self.assertEqual(dec_daead3.decrypt_deterministically(ciphertext1, b'ad'),
                     b'plaintext')
    with self.assertRaises(tink.TinkError):
      _ = dec_daead4.decrypt_deterministically(ciphertext1, b'ad')

    # 2 encrypts with the older key. So 1, 2 and 3 can decrypt it, but not 4.
    ciphertext2 = enc_daead2.encrypt_deterministically(b'plaintext', b'ad')
    self.assertEqual(dec_daead1.decrypt_deterministically(ciphertext2, b'ad'),
                     b'plaintext')
    self.assertEqual(dec_daead2.decrypt_deterministically(ciphertext2, b'ad'),
                     b'plaintext')
    self.assertEqual(dec_daead3.decrypt_deterministically(ciphertext2, b'ad'),
                     b'plaintext')
    with self.assertRaises(tink.TinkError):
      _ = dec_daead4.decrypt_deterministically(ciphertext2, b'ad')

    # 3 encrypts with the newer key. So 2, 3 and 4 can decrypt it, but not 1.
    ciphertext3 = enc_daead3.encrypt_deterministically(b'plaintext', b'ad')
    with self.assertRaises(tink.TinkError):
      _ = dec_daead1.decrypt_deterministically(ciphertext3, b'ad')
    self.assertEqual(dec_daead2.decrypt_deterministically(ciphertext3, b'ad'),
                     b'plaintext')
    self.assertEqual(dec_daead3.decrypt_deterministically(ciphertext3, b'ad'),
                     b'plaintext')
    self.assertEqual(dec_daead4.decrypt_deterministically(ciphertext3, b'ad'),
                     b'plaintext')

    # 4 encrypts with the newer key. So 2, 3 and 4 can decrypt it, but not 1.
    ciphertext4 = enc_daead4.encrypt_deterministically(b'plaintext', b'ad')
    with self.assertRaises(tink.TinkError):
      _ = dec_daead1.decrypt_deterministically(ciphertext4, b'ad')
    self.assertEqual(dec_daead2.decrypt_deterministically(ciphertext4, b'ad'),
                     b'plaintext')
    self.assertEqual(dec_daead3.decrypt_deterministically(ciphertext4, b'ad'),
                     b'plaintext')
    self.assertEqual(dec_daead4.decrypt_deterministically(ciphertext4, b'ad'),
                     b'plaintext')

if __name__ == '__main__':
  absltest.main()
