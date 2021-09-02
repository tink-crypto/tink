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
"""Cross-language tests for Public-Key Signatures."""

# Placeholder for import for type annotations
from typing import Iterable, Text, Tuple

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import signature

from tink.proto import tink_pb2
from tink.testing import keyset_builder
from util import supported_key_types
from util import testing_servers

SUPPORTED_LANGUAGES = (testing_servers
                       .SUPPORTED_LANGUAGES_BY_PRIMITIVE['signature'])


def setUpModule():
  signature.register()
  testing_servers.start('signature')


def tearDownModule():
  testing_servers.stop()


# maps from key_template_name to (key_template, key_type)
_ADDITIONAL_KEY_TEMPLATES = {
    # TODO(b/140101381): Remove this entry, once 'ECDSA_P384_SHA384'
    # is supported in Java.
    'ECDSA_P384_SHA384': (signature.signature_key_templates.ECDSA_P384_SHA384,
                          'EcdsaPrivateKey'),
    'ECDSA_P384_SHA384_IEEE_P1363':
        (signature.signature_key_templates.ECDSA_P384_SHA384_IEEE_P1363,
         'EcdsaPrivateKey'),
}


def all_signature_private_key_template_names() -> Iterable[Text]:
  """Yields all Signature private key template names."""
  for key_type in supported_key_types.SIGNATURE_KEY_TYPES:
    for key_template_name in supported_key_types.KEY_TEMPLATE_NAMES[key_type]:
      yield key_template_name
  for key_template_name in _ADDITIONAL_KEY_TEMPLATES:
    yield key_template_name


class SignatureTest(parameterized.TestCase):

  @parameterized.parameters(all_signature_private_key_template_names())
  def test_sign_verify(self, key_template_name):
    if key_template_name in _ADDITIONAL_KEY_TEMPLATES:
      key_template, key_type = _ADDITIONAL_KEY_TEMPLATES[key_template_name]
      supported_langs = supported_key_types.SUPPORTED_LANGUAGES[key_type]
    else:
      key_template = testing_servers.key_template('java', key_template_name)
      supported_langs = (
          supported_key_types
          .SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[key_template_name])
    self.assertNotEmpty(supported_langs)
    # Take the first supported language to generate the private keyset.
    private_keyset = testing_servers.new_keyset(supported_langs[0],
                                                key_template)
    supported_signers = [
        testing_servers.public_key_sign(lang, private_keyset)
        for lang in supported_langs
    ]
    unsupported_signers = [
        testing_servers.public_key_sign(lang, private_keyset)
        for lang in SUPPORTED_LANGUAGES
        if lang not in supported_langs
    ]
    public_keyset = testing_servers.public_keyset('java', private_keyset)
    supported_verifiers = [
        testing_servers.public_key_verify(lang, public_keyset)
        for lang in supported_langs
    ]
    unsupported_verifiers = [
        testing_servers.public_key_verify(lang, public_keyset)
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
        with self.assertRaises(
            tink.TinkError,
            msg='Language %s supports signature verify with %s unexpectedly' %
            (verifier.lang, key_template_name)):
          verifier.verify(sign, message)
    for signer in unsupported_signers:
      with self.assertRaises(
          tink.TinkError,
          msg='Language %s supports signature sign with %s unexpectedly' %
          (signer.lang, key_template_name)):
        _ = signer.sign(message)


# If the implementations work fine for keysets with single keys, then key
# rotation should work if the primitive wrapper is implemented correctly.
# The wrapper does not depend on the key type, so it should be fine to always
# test with the same key type. The wrapper needs to treat keys with output
# prefix RAW and LEGACY differently, so we also test templates with these
# prefixes.
KEY_ROTATION_TEMPLATES = [
    signature.signature_key_templates.ECDSA_P256,
    keyset_builder.raw_template(signature.signature_key_templates.ECDSA_P256),
    keyset_builder.legacy_template(signature.signature_key_templates.ECDSA_P256)
]


def key_rotation_test_cases(
) -> Iterable[Tuple[Text, Text, tink_pb2.KeyTemplate, tink_pb2.KeyTemplate]]:
  for enc_lang in SUPPORTED_LANGUAGES:
    for dec_lang in SUPPORTED_LANGUAGES:
      for old_key_tmpl in KEY_ROTATION_TEMPLATES:
        for new_key_tmpl in KEY_ROTATION_TEMPLATES:
          yield (enc_lang, dec_lang, old_key_tmpl, new_key_tmpl)


class SignatureKeyRotationTest(parameterized.TestCase):

  @parameterized.parameters(key_rotation_test_cases())
  def test_key_rotation(self, enc_lang, dec_lang, old_key_tmpl, new_key_tmpl):
    # Do a key rotation from an old key generated from old_key_tmpl to a new
    # key generated from new_key_tmpl. Encryption and decryption are done
    # in languages enc_lang and dec_lang.
    builder = keyset_builder.new_keyset_builder()
    older_key_id = builder.add_new_key(old_key_tmpl)
    builder.set_primary_key(older_key_id)
    sign1 = testing_servers.public_key_sign(enc_lang, builder.keyset())
    verify1 = testing_servers.public_key_verify(dec_lang,
                                                builder.public_keyset())
    newer_key_id = builder.add_new_key(new_key_tmpl)
    sign2 = testing_servers.public_key_sign(enc_lang, builder.keyset())
    verify2 = testing_servers.public_key_verify(dec_lang,
                                                builder.public_keyset())

    builder.set_primary_key(newer_key_id)
    sign3 = testing_servers.public_key_sign(enc_lang, builder.keyset())
    verify3 = testing_servers.public_key_verify(dec_lang,
                                                builder.public_keyset())

    builder.disable_key(older_key_id)
    sign4 = testing_servers.public_key_sign(enc_lang, builder.keyset())
    verify4 = testing_servers.public_key_verify(dec_lang,
                                                builder.public_keyset())
    self.assertNotEqual(older_key_id, newer_key_id)

    # 1 signs with the older key. So 1, 2 and 3 can verify it, but not 4.
    data_signature1 = sign1.sign(b'data')
    verify1.verify(data_signature1, b'data')
    verify2.verify(data_signature1, b'data')
    verify3.verify(data_signature1, b'data')
    with self.assertRaises(tink.TinkError):
      verify4.verify(data_signature1, b'data')

    # 2 signs with the older key. So 1, 2 and 3 can verify it, but not 4.
    data_signature2 = sign2.sign(b'data')
    verify1.verify(data_signature2, b'data')
    verify2.verify(data_signature2, b'data')
    verify3.verify(data_signature2, b'data')
    with self.assertRaises(tink.TinkError):
      verify4.verify(data_signature2, b'data')

    # 3 signs with the newer key. So 2, 3 and 4 can verify it, but not 1.
    data_signature3 = sign3.sign(b'data')
    with self.assertRaises(tink.TinkError):
      verify1.verify(data_signature3, b'data')
    verify2.verify(data_signature3, b'data')
    verify3.verify(data_signature3, b'data')
    verify4.verify(data_signature3, b'data')

    # 4 signs with the newer key. So 2, 3 and 4 can verify it, but not 1.
    data_signature4 = sign4.sign(b'data')
    with self.assertRaises(tink.TinkError):
      verify1.verify(data_signature4, b'data')
    verify2.verify(data_signature4, b'data')
    verify3.verify(data_signature4, b'data')
    verify4.verify(data_signature4, b'data')

if __name__ == '__main__':
  absltest.main()
