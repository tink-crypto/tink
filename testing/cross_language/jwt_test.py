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

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import jwt

from util import testing_servers
from util import utilities

SUPPORTED_LANGUAGES = testing_servers.SUPPORTED_LANGUAGES_BY_PRIMITIVE['jwt']


def setUpModule():
  testing_servers.start('jwt')


def tearDownModule():
  testing_servers.stop()


class JwtTest(parameterized.TestCase):

  @parameterized.parameters(utilities.tinkey_template_names_for(jwt.JwtMac))
  def test_compute_verify_jwt_mac(self, key_template_name):
    supported_langs = utilities.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[
        key_template_name]
    self.assertNotEmpty(supported_langs)
    key_template = utilities.KEY_TEMPLATE[key_template_name]
    # Take the first supported language to generate the keyset.
    keyset = testing_servers.new_keyset(supported_langs[0], key_template)
    supported_jwt_macs = []
    for lang in supported_langs:
      supported_jwt_macs.append(
          testing_servers.remote_primitive(lang, keyset, jwt.JwtMac))
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

  @parameterized.parameters(
      utilities.tinkey_template_names_for(jwt.JwtPublicKeySign))
  def test_jwt_public_key_sign_verify(self, key_template_name):
    supported_langs = utilities.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[
        key_template_name]
    key_template = utilities.KEY_TEMPLATE[key_template_name]
    self.assertNotEmpty(supported_langs)
    # Take the first supported language to generate the private keyset.
    private_keyset = testing_servers.new_keyset(supported_langs[0],
                                                key_template)
    supported_signers = {}
    for lang in supported_langs:
      supported_signers[lang] = testing_servers.remote_primitive(
          lang, private_keyset, jwt.JwtPublicKeySign)
    public_keyset = testing_servers.public_keyset('java', private_keyset)
    supported_verifiers = {}
    for lang in supported_langs:
      supported_verifiers[lang] = testing_servers.remote_primitive(
          lang, public_keyset, jwt.JwtPublicKeyVerify)
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    raw_jwt = jwt.new_raw_jwt(
        issuer='issuer', expiration=now + datetime.timedelta(seconds=100))
    for signer in supported_signers.values():
      compact = signer.sign_and_encode(raw_jwt)
      validator = jwt.new_validator(expected_issuer='issuer', fixed_now=now)
      for verifier in supported_verifiers.values():
        verified_jwt = verifier.verify_and_decode(compact, validator)
        self.assertEqual(verified_jwt.issuer(), 'issuer')

  @parameterized.parameters(
      utilities.tinkey_template_names_for(jwt.JwtPublicKeySign))
  def test_jwt_public_key_sign_export_import_verify(self, key_template_name):
    supported_langs = utilities.SUPPORTED_LANGUAGES_BY_TEMPLATE_NAME[
        key_template_name]
    self.assertNotEmpty(supported_langs)
    key_template = utilities.KEY_TEMPLATE[key_template_name]
    # Take the first supported language to generate the private keyset.
    private_keyset = testing_servers.new_keyset(supported_langs[0],
                                                key_template)
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    raw_jwt = jwt.new_raw_jwt(
        issuer='issuer', expiration=now + datetime.timedelta(seconds=100))
    validator = jwt.new_validator(expected_issuer='issuer', fixed_now=now)

    for lang1 in supported_langs:
      # in lang1: sign token and export public keyset to a JWK set
      signer = testing_servers.remote_primitive(lang1, private_keyset,
                                                jwt.JwtPublicKeySign)
      compact = signer.sign_and_encode(raw_jwt)
      public_keyset = testing_servers.public_keyset(lang1, private_keyset)
      public_jwk_set = testing_servers.jwk_set_from_keyset(lang1, public_keyset)
      for lang2 in supported_langs:
        # in lang2: import the public JWK set and verify the token
        public_keyset = testing_servers.jwk_set_to_keyset(lang2, public_jwk_set)
        verifier = testing_servers.remote_primitive(lang2, public_keyset,
                                                    jwt.JwtPublicKeyVerify)
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
          verifier = testing_servers.remote_primitive(lang2, public_keyset,
                                                      jwt.JwtPublicKeyVerify)
          with self.assertRaises(
              tink.TinkError,
              msg='%s accepts tokens with an incorrect kid unexpectedly' %
              lang2):
            verifier.verify_and_decode(compact, validator)

          # Remove the "kid" property of the JWK.
          del jwks['keys'][0]['kid']
          public_keyset = testing_servers.jwk_set_to_keyset(
              lang2, json.dumps(jwks))
          verifier = testing_servers.remote_primitive(lang2, public_keyset,
                                                      jwt.JwtPublicKeyVerify)
          verified_jwt = verifier.verify_and_decode(compact, validator)
          self.assertEqual(verified_jwt.issuer(), 'issuer')
        else:
          # Add a "kid" property of the JWK.
          jwks['keys'][0]['kid'] = 'unknown kid'
          public_keyset = testing_servers.jwk_set_to_keyset(
              lang2, json.dumps(jwks))
          verifier = testing_servers.remote_primitive(lang2, public_keyset,
                                                      jwt.JwtPublicKeyVerify)
          verified_jwt = verifier.verify_and_decode(compact, validator)
          self.assertEqual(verified_jwt.issuer(), 'issuer')


if __name__ == '__main__':
  absltest.main()
