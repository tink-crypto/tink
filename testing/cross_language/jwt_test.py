# Copyright 2021 Google LLC
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
"""Cross-language tests for the JWT primitives."""

import datetime
import json
from typing import Iterable

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import jwt

from util import supported_key_types
from util import testing_servers

SUPPORTED_LANGUAGES = testing_servers.SUPPORTED_LANGUAGES_BY_PRIMITIVE['jwt']


def setUpModule():
  testing_servers.start('jwt')


def tearDownModule():
  testing_servers.stop()


# maps from key_template_name to supported_langs. Templates for a key type
# that aren't widely deployed across a language.
_ADDITIONAL_KEY_TEMPLATES = {
    # JWT_RS in development in go b/230489047
    'JWT_RS256_2048_F4': ['cc', 'java', 'python'],
    'JWT_RS256_2048_F4_RAW': ['cc', 'java', 'python'],
    'JWT_RS256_3072_F4': ['cc', 'java', 'python'],
    'JWT_RS256_3072_F4_RAW': ['cc', 'java', 'python'],
    'JWT_RS384_3072_F4': ['cc', 'java', 'python'],
    'JWT_RS384_3072_F4_RAW': ['cc', 'java', 'python'],
    'JWT_RS512_4096_F4': ['cc', 'java', 'python'],
    'JWT_RS512_4096_F4_RAW': ['cc', 'java', 'python'],
    # JWT PS in development in go b/230489047
    'JWT_PS256_2048_F4': ['cc', 'java', 'python'],
    'JWT_PS256_2048_F4_RAW': ['cc', 'java', 'python'],
    'JWT_PS256_3072_F4': ['cc', 'java', 'python'],
    'JWT_PS256_3072_F4_RAW': ['cc', 'java', 'python'],
    'JWT_PS384_3072_F4': ['cc', 'java', 'python'],
    'JWT_PS384_3072_F4_RAW': ['cc', 'java', 'python'],
    'JWT_PS512_4096_F4': ['cc', 'java', 'python'],
    'JWT_PS512_4096_F4_RAW': ['cc', 'java', 'python'],
}


def all_jwt_mac_key_template_names() -> Iterable[str]:
  """Yields all JWT MAC key template names."""
  for key_type in supported_key_types.JWT_MAC_KEY_TYPES:
    for key_template_name in supported_key_types.KEY_TEMPLATE_NAMES[key_type]:
      yield key_template_name


def all_jwt_signature_key_template_names() -> Iterable[str]:
  """Yields all JWT signature key template names."""
  for key_type in supported_key_types.JWT_SIGNATURE_KEY_TYPES:
    for key_template_name in supported_key_types.KEY_TEMPLATE_NAMES[key_type]:
      yield key_template_name


class JwtTest(parameterized.TestCase):

  @parameterized.parameters(all_jwt_mac_key_template_names())
  def test_compute_verify_jwt_mac(self, key_template_name):
    supported_langs = supported_key_types.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[
        key_template_name]
    self.assertNotEmpty(supported_langs)
    key_template = supported_key_types.KEY_TEMPLATE[key_template_name]
    # Take the first supported language to generate the keyset.
    keyset = testing_servers.new_keyset(supported_langs[0], key_template)
    supported_jwt_macs = [
        testing_servers.jwt_mac(lang, keyset) for lang in supported_langs
    ]
    unsupported_jwt_macs = [
        testing_servers.jwt_mac(lang, keyset)
        for lang in SUPPORTED_LANGUAGES
        if lang not in supported_langs
    ]
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    raw_jwt = jwt.new_raw_jwt(
        issuer='issuer',
        expiration=now + datetime.timedelta(seconds=100))
    for p in supported_jwt_macs:
      compact = p.compute_mac_and_encode(raw_jwt)
      validator = jwt.new_validator(expected_issuer='issuer', fixed_now=now)
      for p2 in supported_jwt_macs:
        verified_jwt = p2.verify_mac_and_decode(compact, validator)
        self.assertEqual(verified_jwt.issuer(), 'issuer')
      for p2 in unsupported_jwt_macs:
        with self.assertRaises(
            tink.TinkError,
            msg='%s supports verify_mac_and_decode with %s unexpectedly'
            % (p2.lang, key_template_name)):
          p2.verify_mac_and_decode(compact, validator)
    for p in unsupported_jwt_macs:
      with self.assertRaises(
          tink.TinkError,
          msg='%s supports compute_mac_and_encode with %s unexpectedly' %
          (p.lang, key_template_name)):
        p.compute_mac_and_encode(raw_jwt)

  @parameterized.parameters(all_jwt_signature_key_template_names())
  def test_jwt_public_key_sign_verify(self, key_template_name):
    if key_template_name in _ADDITIONAL_KEY_TEMPLATES:
      supported_langs = _ADDITIONAL_KEY_TEMPLATES[key_template_name]
      key_template = supported_key_types.KEY_TEMPLATE[key_template_name]
    else:
      supported_langs = supported_key_types.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[
          key_template_name]
      key_template = supported_key_types.KEY_TEMPLATE[key_template_name]
    self.assertNotEmpty(supported_langs)
    # Take the first supported language to generate the private keyset.
    private_keyset = testing_servers.new_keyset(supported_langs[0],
                                                key_template)
    supported_signers = [
        testing_servers.jwt_public_key_sign(lang, private_keyset)
        for lang in supported_langs
    ]
    unsupported_signers = [
        testing_servers.jwt_public_key_sign(lang, private_keyset)
        for lang in SUPPORTED_LANGUAGES
        if lang not in supported_langs
    ]
    public_keyset = testing_servers.public_keyset('java', private_keyset)
    supported_verifiers = [
        testing_servers.jwt_public_key_verify(lang, public_keyset)
        for lang in supported_langs
    ]
    unsupported_verifiers = [
        testing_servers.jwt_public_key_verify(lang, public_keyset)
        for lang in SUPPORTED_LANGUAGES
        if lang not in supported_langs
    ]
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    raw_jwt = jwt.new_raw_jwt(
        issuer='issuer', expiration=now + datetime.timedelta(seconds=100))
    for signer in supported_signers:
      compact = signer.sign_and_encode(raw_jwt)
      validator = jwt.new_validator(expected_issuer='issuer', fixed_now=now)
      for verifier in supported_verifiers:
        verified_jwt = verifier.verify_and_decode(compact, validator)
        self.assertEqual(verified_jwt.issuer(), 'issuer')
      for verifier in unsupported_verifiers:
        with self.assertRaises(
            tink.TinkError,
            msg='%s supports jwt_public_key_verify with %s unexpectedly' %
            (verifier.lang, key_template_name)):
          verifier.verify_and_decode(compact, validator)
    for signer in unsupported_signers:
      with self.assertRaises(
          tink.TinkError,
          msg='%s supports jwt_public_key_sign with %s unexpectedly' %
          (signer.lang, key_template_name)):
        _ = signer.sign_and_encode(raw_jwt)

  @parameterized.parameters(all_jwt_signature_key_template_names())
  def test_jwt_public_key_sign_export_import_verify(self, key_template_name):
    supported_langs = supported_key_types.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[
        key_template_name]
    self.assertNotEmpty(supported_langs)
    key_template = supported_key_types.KEY_TEMPLATE[key_template_name]
    # Take the first supported language to generate the private keyset.
    private_keyset = testing_servers.new_keyset(supported_langs[0],
                                                key_template)
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    raw_jwt = jwt.new_raw_jwt(
        issuer='issuer', expiration=now + datetime.timedelta(seconds=100))
    validator = jwt.new_validator(expected_issuer='issuer', fixed_now=now)

    for lang1 in supported_langs:
      # in lang1: sign token and export public keyset to a JWK set
      signer = testing_servers.jwt_public_key_sign(lang1, private_keyset)
      compact = signer.sign_and_encode(raw_jwt)
      public_keyset = testing_servers.public_keyset(lang1, private_keyset)
      public_jwk_set = testing_servers.jwk_set_from_keyset(lang1, public_keyset)
      for lang2 in supported_langs:
        # in lang2: import the public JWK set and verify the token
        public_keyset = testing_servers.jwk_set_to_keyset(lang2, public_jwk_set)
        verifier = testing_servers.jwt_public_key_verify(lang2, public_keyset)
        verified_jwt = verifier.verify_and_decode(compact, validator)
        self.assertEqual(verified_jwt.issuer(), 'issuer')

        # Additional tests for the "kid" property of the JWK and the "kid"
        # header of the token. Either of them may be missing, but they must not
        # have different values.
        jwks = json.loads(public_jwk_set)
        has_kid = 'kid' in jwks['keys'][0]
        if has_kid:
          # Change the "kid" property of the JWK.
          jwks['keys'][0]['kid'] = 'unknown kid'
          public_keyset = testing_servers.jwk_set_to_keyset(
              lang2, json.dumps(jwks))
          verifier = testing_servers.jwt_public_key_verify(lang2, public_keyset)
          with self.assertRaises(
              tink.TinkError,
              msg='%s accepts tokens with an incorrect kid unexpectedly' %
              lang2):
            verifier.verify_and_decode(compact, validator)

          # Remove the "kid" property of the JWK.
          del jwks['keys'][0]['kid']
          public_keyset = testing_servers.jwk_set_to_keyset(
              lang2, json.dumps(jwks))
          verifier = testing_servers.jwt_public_key_verify(lang2, public_keyset)
          verified_jwt = verifier.verify_and_decode(compact, validator)
          self.assertEqual(verified_jwt.issuer(), 'issuer')
        else:
          # Add a "kid" property of the JWK.
          jwks['keys'][0]['kid'] = 'unknown kid'
          public_keyset = testing_servers.jwk_set_to_keyset(
              lang2, json.dumps(jwks))
          verifier = testing_servers.jwt_public_key_verify(lang2, public_keyset)
          verified_jwt = verifier.verify_and_decode(compact, validator)
          self.assertEqual(verified_jwt.issuer(), 'issuer')


if __name__ == '__main__':
  absltest.main()
