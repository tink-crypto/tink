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
"""Cross-language tests for Hybrid Encryption."""

# Placeholder for import for type annotations
from typing import Iterable, Text, Tuple

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import hybrid

from tink.proto import tink_pb2
from tink.testing import keyset_builder
from util import supported_key_types
from util import testing_servers

SUPPORTED_LANGUAGES = testing_servers.SUPPORTED_LANGUAGES_BY_PRIMITIVE['hybrid']


def setUpModule():
  hybrid.register()
  testing_servers.start('hybrid')


def tearDownModule():
  testing_servers.stop()


def all_hybrid_private_key_template_names() -> Iterable[Text]:
  """Yields all Hybrid Encryption private key template names."""
  for key_type in supported_key_types.HYBRID_PRIVATE_KEY_TYPES:
    for key_template_name in supported_key_types.KEY_TEMPLATE_NAMES[key_type]:
      yield key_template_name


class HybridEncryptionTest(parameterized.TestCase):

  @parameterized.parameters(all_hybrid_private_key_template_names())
  def test_encrypt_decrypt(self, key_template_name):
    supported_langs = supported_key_types.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[
        key_template_name]
    self.assertNotEmpty(supported_langs)
    key_template = supported_key_types.KEY_TEMPLATE[key_template_name]
    # Take the first supported language to generate the private keyset.
    private_keyset = testing_servers.new_keyset(supported_langs[0],
                                                key_template)
    supported_decs = [
        testing_servers.hybrid_decrypt(lang, private_keyset)
        for lang in supported_langs
    ]
    unsupported_decs = [
        testing_servers.hybrid_decrypt(lang, private_keyset)
        for lang in SUPPORTED_LANGUAGES
        if lang not in supported_langs
    ]
    public_keyset = testing_servers.public_keyset(supported_langs[0],
                                                  private_keyset)
    supported_encs = [
        testing_servers.hybrid_encrypt(lang, public_keyset)
        for lang in supported_langs
    ]
    unsupported_encs = [
        testing_servers.hybrid_encrypt(lang, public_keyset)
        for lang in testing_servers.LANGUAGES
        if lang not in supported_langs
    ]
    for enc in supported_encs:
      plaintext = (
          b'This is some plaintext message to be encrypted using key_template '
          b'%s in %s.' % (key_template_name.encode('utf8'),
                          enc.lang.encode('utf8')))
      context_info = (
          b'Some context info for %s using %s for encryption.' %
          (key_template_name.encode('utf8'), enc.lang.encode('utf8')))
      ciphertext = enc.encrypt(plaintext, context_info)
      for dec in supported_decs:
        output = dec.decrypt(ciphertext, context_info)
        self.assertEqual(output, plaintext)
      for dec in unsupported_decs:
        with self.assertRaises(
            tink.TinkError,
            msg='Language %s supports hybrid decrypt with %s unexpectedly' %
            (dec.lang, key_template_name)):
          dec.decrypt(ciphertext, context_info)
    for enc in unsupported_encs:
      with self.assertRaises(
          tink.TinkError,
          msg='Language %s supports hybrid encrypt with %s unexpectedly' % (
              enc.lang, key_template_name)):
        enc.encrypt(b'plaintext', b'context_info')


# If the implementations work fine for keysets with single keys, then key
# rotation should work if the primitive wrapper is implemented correctly.
# These wrappers do not depend on the key type, so it should be fine to always
# test with the same key type. But since the wrapper needs to treat keys
# with output prefix RAW differently, we also include such a template for that.
KEY_ROTATION_TEMPLATES = [
    hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM,
    keyset_builder.raw_template(
        hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM)
]


def key_rotation_test_cases(
) -> Iterable[Tuple[Text, Text, tink_pb2.KeyTemplate, tink_pb2.KeyTemplate]]:
  for enc_lang in SUPPORTED_LANGUAGES:
    for dec_lang in SUPPORTED_LANGUAGES:
      for old_key_tmpl in KEY_ROTATION_TEMPLATES:
        for new_key_tmpl in KEY_ROTATION_TEMPLATES:
          yield (enc_lang, dec_lang, old_key_tmpl, new_key_tmpl)


class HybridEncryptionKeyRotationTest(parameterized.TestCase):

  @parameterized.parameters(key_rotation_test_cases())
  def test_key_rotation(self, enc_lang, dec_lang, old_key_tmpl, new_key_tmpl):
    # Do a key rotation from an old key generated from old_key_tmpl to a new
    # key generated from new_key_tmpl. Encryption and decryption are done
    # in languages enc_lang and dec_lang.
    builder = keyset_builder.new_keyset_builder()
    older_key_id = builder.add_new_key(old_key_tmpl)
    builder.set_primary_key(older_key_id)
    dec1 = testing_servers.hybrid_decrypt(enc_lang, builder.keyset())
    enc1 = testing_servers.hybrid_encrypt(dec_lang, builder.public_keyset())
    newer_key_id = builder.add_new_key(new_key_tmpl)
    dec2 = testing_servers.hybrid_decrypt(enc_lang, builder.keyset())
    enc2 = testing_servers.hybrid_encrypt(dec_lang, builder.public_keyset())

    builder.set_primary_key(newer_key_id)
    dec3 = testing_servers.hybrid_decrypt(enc_lang, builder.keyset())
    enc3 = testing_servers.hybrid_encrypt(dec_lang, builder.public_keyset())

    builder.disable_key(older_key_id)
    dec4 = testing_servers.hybrid_decrypt(enc_lang, builder.keyset())
    enc4 = testing_servers.hybrid_encrypt(dec_lang, builder.public_keyset())
    self.assertNotEqual(older_key_id, newer_key_id)

    # p1 encrypts with the older key. So p1, p2 and p3 can decrypt it,
    # but not p4.
    ciphertext1 = enc1.encrypt(b'plaintext', b'context')
    self.assertEqual(dec1.decrypt(ciphertext1, b'context'), b'plaintext')
    self.assertEqual(dec2.decrypt(ciphertext1, b'context'), b'plaintext')
    self.assertEqual(dec3.decrypt(ciphertext1, b'context'), b'plaintext')
    with self.assertRaises(tink.TinkError):
      _ = dec4.decrypt(ciphertext1, b'context')

    # p2 encrypts with the older key. So p1, p2 and p3 can decrypt it,
    # but not p4.
    ciphertext2 = enc2.encrypt(b'plaintext', b'context')
    self.assertEqual(dec1.decrypt(ciphertext2, b'context'), b'plaintext')
    self.assertEqual(dec2.decrypt(ciphertext2, b'context'), b'plaintext')
    self.assertEqual(dec3.decrypt(ciphertext2, b'context'), b'plaintext')
    with self.assertRaises(tink.TinkError):
      _ = dec4.decrypt(ciphertext2, b'context')

    # p3 encrypts with the newer key. So p2, p3 and p4 can decrypt it,
    # but not p1.
    ciphertext3 = enc3.encrypt(b'plaintext', b'context')
    with self.assertRaises(tink.TinkError):
      _ = dec1.decrypt(ciphertext3, b'context')
    self.assertEqual(dec2.decrypt(ciphertext3, b'context'), b'plaintext')
    self.assertEqual(dec3.decrypt(ciphertext3, b'context'), b'plaintext')
    self.assertEqual(dec4.decrypt(ciphertext3, b'context'), b'plaintext')

    # p4 encrypts with the newer key. So p2, p3 and p4 can decrypt it,
    # but not p1.
    ciphertext4 = enc4.encrypt(b'plaintext', b'context')
    with self.assertRaises(tink.TinkError):
      _ = dec1.decrypt(ciphertext4, b'context')
    self.assertEqual(dec2.decrypt(ciphertext4, b'context'), b'plaintext')
    self.assertEqual(dec3.decrypt(ciphertext4, b'context'), b'plaintext')
    self.assertEqual(dec4.decrypt(ciphertext4, b'context'), b'plaintext')


if __name__ == '__main__':
  absltest.main()
