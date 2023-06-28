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

from typing import Iterable, List, Tuple

from absl.testing import absltest
from absl.testing import parameterized
import tink
from tink import aead

from tink.proto import tink_pb2
from tink.testing import keyset_builder
import tink_config
from util import testing_servers
from util import utilities

SUPPORTED_LANGUAGES = testing_servers.SUPPORTED_LANGUAGES_BY_PRIMITIVE['aead']


def setUpModule():
  aead.register()
  testing_servers.start('aead')


def tearDownModule():
  testing_servers.stop()


# Fake KMS keys are base64-encoded keysets. Each server must register a
# fake KmsClient that can handle these keys.
_FAKE_KMS_KEY_URI = (
    'fake-kms://CM2b3_MDElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRv'
    'LnRpbmsuQWVzR2NtS2V5EhIaEIK75t5L-adlUwVhWvRuWUwYARABGM2b3_MDIAE')


# maps from key_template_name to (key_template, supported_langs).  Contains all
# templates we want to test which do not have a name in Tinkey.
_ADDITIONAL_KEY_TEMPLATES = {
    '_FAKE_KMS_AEAD': (
        aead.aead_key_templates.create_kms_aead_key_template(_FAKE_KMS_KEY_URI),
        tink_config.supported_languages_for_key_type('KmsAeadKey'),
    ),
    # Since the key type KmsEnvelopeAeadKey is supported by all languages, the
    # following templates should be supported if the DEK Template is supported
    # by the language.
    '_FAKE_KMS_ENVELOPE_AEAD_WITH_AES128_GCM': (
        aead.aead_key_templates.create_kms_envelope_aead_key_template(
            _FAKE_KMS_KEY_URI, aead.aead_key_templates.AES128_GCM
        ),
        utilities.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME['AES128_GCM'],
    ),
    '_FAKE_KMS_ENVELOPE_AEAD_WITH_AES256_GCM': (
        aead.aead_key_templates.create_kms_envelope_aead_key_template(
            _FAKE_KMS_KEY_URI, aead.aead_key_templates.AES256_GCM
        ),
        utilities.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME['AES256_GCM'],
    ),
    '_FAKE_KMS_ENVELOPE_AEAD_WITH_AES128_EAX': (
        aead.aead_key_templates.create_kms_envelope_aead_key_template(
            _FAKE_KMS_KEY_URI, aead.aead_key_templates.AES128_EAX
        ),
        utilities.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME['AES128_EAX'],
    ),
    '_FAKE_KMS_ENVELOPE_AEAD_WITH_AES256_EAX': (
        aead.aead_key_templates.create_kms_envelope_aead_key_template(
            _FAKE_KMS_KEY_URI, aead.aead_key_templates.AES256_EAX
        ),
        utilities.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME['AES256_EAX'],
    ),
    '_FAKE_KMS_ENVELOPE_AEAD_WITH_AES128_GCM_SIV': (
        aead.aead_key_templates.create_kms_envelope_aead_key_template(
            _FAKE_KMS_KEY_URI, aead.aead_key_templates.AES128_GCM_SIV
        ),
        utilities.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME['AES128_GCM_SIV'],
    ),
    '_FAKE_KMS_ENVELOPE_AEAD_WITH_AES256_GCM_SIV': (
        aead.aead_key_templates.create_kms_envelope_aead_key_template(
            _FAKE_KMS_KEY_URI, aead.aead_key_templates.AES256_GCM_SIV
        ),
        utilities.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME['AES256_GCM_SIV'],
    ),
    '_FAKE_KMS_ENVELOPE_AEAD_WITH_AES128_CTR_HMAC_SHA256': (
        aead.aead_key_templates.create_kms_envelope_aead_key_template(
            _FAKE_KMS_KEY_URI, aead.aead_key_templates.AES128_CTR_HMAC_SHA256
        ),
        utilities.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[
            'AES128_CTR_HMAC_SHA256'
        ],
    ),
    '_FAKE_KMS_ENVELOPE_AEAD_WITH_AES256_CTR_HMAC_SHA256': (
        aead.aead_key_templates.create_kms_envelope_aead_key_template(
            _FAKE_KMS_KEY_URI, aead.aead_key_templates.AES256_CTR_HMAC_SHA256
        ),
        utilities.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[
            'AES256_CTR_HMAC_SHA256'
        ],
    ),
    '_FAKE_KMS_ENVELOPE_AEAD_WITH_CHACHA20_POLY1305': (
        aead.aead_key_templates.create_kms_envelope_aead_key_template(
            _FAKE_KMS_KEY_URI, utilities.KEY_TEMPLATE['CHACHA20_POLY1305']
        ),
        utilities.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME['CHACHA20_POLY1305'],
    ),
    '_FAKE_KMS_ENVELOPE_AEAD_WITH_XCHACHA20_POLY1305': (
        aead.aead_key_templates.create_kms_envelope_aead_key_template(
            _FAKE_KMS_KEY_URI, aead.aead_key_templates.XCHACHA20_POLY1305
        ),
        utilities.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME['XCHACHA20_POLY1305'],
    ),
}


class AeadPythonTest(parameterized.TestCase):

  def _create_aeads_ignore_errors(self,
                                  keyset: bytes) -> List[Tuple[aead.Aead, str]]:
    """Creates AEADs for the given keyset in each language.

    Args:
      keyset: A keyset as a serialized 'keyset' proto.

    Returns:
      A list of pairs (aead, language)
    """

    result = []
    for lang in utilities.ALL_LANGUAGES:
      try:
        aead_p = testing_servers.remote_primitive(lang, keyset, aead.Aead)
        result.append((aead_p, lang))
      except tink.TinkError:
        pass
    return result

  def _langs_from_key_template_name(self, key_template_name: str) -> List[str]:
    if key_template_name in _ADDITIONAL_KEY_TEMPLATES:
      _, supported_langs = _ADDITIONAL_KEY_TEMPLATES[key_template_name]
      return supported_langs
    else:
      return utilities.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[key_template_name]

  def _as_proto_template(self, key_template_name: str) -> tink_pb2.KeyTemplate:
    if key_template_name in _ADDITIONAL_KEY_TEMPLATES:
      key_template, _ = _ADDITIONAL_KEY_TEMPLATES[key_template_name]
      return key_template
    else:
      return utilities.KEY_TEMPLATE[key_template_name]

  @parameterized.parameters([
      *utilities.tinkey_template_names_for(aead.Aead),
      *_ADDITIONAL_KEY_TEMPLATES.keys()
  ])
  def test_encrypt_decrypt(self, key_template_name):
    langs = self._langs_from_key_template_name(key_template_name)
    self.assertNotEmpty(langs)
    proto_template = self._as_proto_template(key_template_name)
    # Take the first supported language to generate the keyset.
    keyset = testing_servers.new_keyset(langs[0], proto_template)

    supported_aeads = self._create_aeads_ignore_errors(keyset)
    self.assertEqual(set([lang for (_, lang) in supported_aeads]), set(langs))
    for (p, lang) in supported_aeads:
      plaintext = (
          b'This is some plaintext message to be encrypted using key_template '
          b'%s using %s for encryption.' %
          (key_template_name.encode('utf8'), lang.encode('utf8')))
      associated_data = (
          b'Some associated data for %s using %s for encryption.' %
          (key_template_name.encode('utf8'), lang.encode('utf8')))
      ciphertext = p.encrypt(plaintext, associated_data)
      for (p2, lang2) in supported_aeads:
        output = p2.decrypt(ciphertext, associated_data)
        self.assertEqual(
            output, plaintext,
            'While encrypting in %s an decrypting in %s' % (lang, lang2))

  @parameterized.parameters(
      tink_config.supported_languages_for_key_type('KmsEnvelopeAeadKey')
  )
  def test_envelope_encryption_rejects_envelope_templates_as_dek(self, lang):
    dek_template = (
        aead.aead_key_templates.create_kms_envelope_aead_key_template(
            kek_uri=_FAKE_KMS_KEY_URI,
            dek_template=aead.aead_key_templates.AES128_GCM,
        )
    )
    template = aead.aead_key_templates.create_kms_envelope_aead_key_template(
        kek_uri=_FAKE_KMS_KEY_URI, dek_template=dek_template
    )
    with self.assertRaises(tink.TinkError):
      _ = testing_servers.new_keyset(lang, template)

  @parameterized.parameters(
      tink_config.supported_languages_for_key_type('KmsAeadKey')
  )
  def test_envelope_encryption_rejects_kms_templates_as_dek(self, lang):
    dek_template = aead.aead_key_templates.create_kms_aead_key_template(
        key_uri=_FAKE_KMS_KEY_URI
    )
    template = aead.aead_key_templates.create_kms_envelope_aead_key_template(
        kek_uri=_FAKE_KMS_KEY_URI, dek_template=dek_template
    )
    with self.assertRaises(tink.TinkError):
      _ = testing_servers.new_keyset(lang, template)


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
) -> Iterable[Tuple[str, str, tink_pb2.KeyTemplate, tink_pb2.KeyTemplate]]:
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
    enc_aead1 = testing_servers.remote_primitive(enc_lang, builder.keyset(),
                                                 aead.Aead)
    dec_aead1 = testing_servers.remote_primitive(dec_lang, builder.keyset(),
                                                 aead.Aead)
    newer_key_id = builder.add_new_key(new_key_tmpl)
    enc_aead2 = testing_servers.remote_primitive(enc_lang, builder.keyset(),
                                                 aead.Aead)
    dec_aead2 = testing_servers.remote_primitive(dec_lang, builder.keyset(),
                                                 aead.Aead)

    builder.set_primary_key(newer_key_id)
    enc_aead3 = testing_servers.remote_primitive(enc_lang, builder.keyset(),
                                                 aead.Aead)
    dec_aead3 = testing_servers.remote_primitive(dec_lang, builder.keyset(),
                                                 aead.Aead)

    builder.disable_key(older_key_id)
    enc_aead4 = testing_servers.remote_primitive(enc_lang, builder.keyset(),
                                                 aead.Aead)
    dec_aead4 = testing_servers.remote_primitive(dec_lang, builder.keyset(),
                                                 aead.Aead)

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
