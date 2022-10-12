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
"""Tests keyset validation.

Currently only tests if keysets without a primary key are properly handled.
"""

import datetime
from typing import Any
from typing import Iterable
from typing import Tuple

from absl.testing import absltest
from absl.testing import parameterized
import tink
from tink import aead
from tink import daead
from tink import hybrid
from tink import jwt
from tink import mac
from tink import prf
from tink import signature

from tink.proto import tink_pb2
import tink_config
from util import testing_servers
from util import utilities


def unset_primary(keyset: bytes) -> bytes:
  """Parses keyset and generates modified keyset without primary key."""
  keyset_proto = tink_pb2.Keyset.FromString(keyset)
  keyset_proto.ClearField('primary_key_id')
  return keyset_proto.SerializeToString()


def test_cases(primitive: Any) -> Iterable[Tuple[str, str]]:
  for key_type in tink_config.key_types_for_primitive(primitive):
    for key_template_name in utilities.KEY_TEMPLATE_NAMES[key_type]:
      for lang in tink_config.supported_languages_for_key_type(key_type):
        yield (key_template_name, lang)


def setUpModule():
  testing_servers.start('key_version')


def tearDownModule():
  testing_servers.stop()


class KeysetValidationTest(parameterized.TestCase):
  """These tests verify keysets are properly validated."""

  @parameterized.parameters(test_cases(aead.Aead))
  def test_aead_without_primary(self, key_template_name, lang):
    """Unsets the primary key and tries to use an AEAD primitive."""
    template = utilities.KEY_TEMPLATE[key_template_name]
    keyset = testing_servers.new_keyset(lang, template)

    with self.assertRaises(tink.TinkError):
      _ = testing_servers.remote_primitive(lang, unset_primary(keyset),
                                           aead.Aead)

  @parameterized.parameters(test_cases(daead.DeterministicAead))
  def test_daead_without_primary(self, key_template_name, lang):
    """Unsets the primary key and tries to use a DAEAD primitive."""
    template = utilities.KEY_TEMPLATE[key_template_name]
    keyset = testing_servers.new_keyset(lang, template)
    with self.assertRaises(tink.TinkError):
      _ = testing_servers.remote_primitive(lang, unset_primary(keyset),
                                           daead.DeterministicAead)

  @parameterized.parameters(test_cases(mac.Mac))
  def test_mac_without_primary(self, key_template_name, lang):
    """Unsets the primary key and tries to use a MAC primitive."""
    template = utilities.KEY_TEMPLATE[key_template_name]
    keyset = testing_servers.new_keyset(lang, template)
    with self.assertRaises(tink.TinkError):
      testing_servers.remote_primitive(lang, unset_primary(keyset), mac.Mac)

  @parameterized.parameters(test_cases(prf.PrfSet))
  def test_prf_without_primary(self, key_template_name, lang):
    """Unsets the primary key and tries to use a PRF set primitive."""
    template = utilities.KEY_TEMPLATE[key_template_name]
    keyset = testing_servers.new_keyset(lang, template)
    with self.assertRaises(tink.TinkError):
      _ = testing_servers.remote_primitive(lang, unset_primary(keyset),
                                           prf.PrfSet)

  @parameterized.parameters(test_cases(signature.PublicKeySign))
  def test_signature_without_primary(self, key_template_name, lang):
    """Unsets the primary key and tries to sign and verify signatures."""
    template = utilities.KEY_TEMPLATE[key_template_name]
    private_keyset = testing_servers.new_keyset(lang, template)
    public_keyset = testing_servers.public_keyset(lang, private_keyset)
    signer = testing_servers.remote_primitive(lang, private_keyset,
                                              signature.PublicKeySign)
    sig = signer.sign(b'foo')
    verifier = testing_servers.remote_primitive(lang, public_keyset,
                                                signature.PublicKeyVerify)
    verifier.verify(sig, b'foo')
    private_keyset_without_primary = unset_primary(private_keyset)
    public_keyset_without_primary = unset_primary(public_keyset)
    with self.assertRaises(tink.TinkError):
      _ = testing_servers.remote_primitive(
          lang, private_keyset_without_primary, signature.PublicKeySign)
    if lang not in ['java', 'python']:
      with self.assertRaises(tink.TinkError):
        _ = testing_servers.remote_primitive(
            lang, public_keyset_without_primary, signature.PublicKeyVerify)
    if lang in ['java', 'python']:
      # TODO(b/252792776) This should fail.
      verifier_without_primary = testing_servers.remote_primitive(
          lang, public_keyset_without_primary, signature.PublicKeyVerify)
      verifier_without_primary.verify(sig, b'foo')

  @parameterized.parameters(test_cases(hybrid.HybridDecrypt))
  def test_hybrid_without_primary(self, key_template_name, lang):
    """Unsets the primary key and tries to use hybrid encryption."""
    template = utilities.KEY_TEMPLATE[key_template_name]
    private_keyset = testing_servers.new_keyset(lang, template)
    public_keyset = testing_servers.public_keyset(lang, private_keyset)

    private_keyset_without_primary = unset_primary(private_keyset)
    with self.assertRaises(tink.TinkError):
      testing_servers.remote_primitive(
          lang, unset_primary(private_keyset_without_primary),
          hybrid.HybridDecrypt)

    public_keyset_without_primary = unset_primary(public_keyset)
    with self.assertRaises(tink.TinkError):
      enc_without_primary = testing_servers.remote_primitive(
          lang, public_keyset_without_primary, hybrid.HybridEncrypt)
      # TODO(b/228140127) This should fail above already.
      enc_without_primary.encrypt(b'foo', b'context_info')

  @parameterized.parameters(test_cases(jwt.JwtPublicKeySign))
  def test_jwt_signature_without_primary(self, key_template_name, lang):
    """Unsets the primary key and tries to sign and verify JWT signatures."""
    template = utilities.KEY_TEMPLATE[key_template_name]
    private_keyset = testing_servers.new_keyset(lang, template)
    public_keyset = testing_servers.public_keyset(lang, private_keyset)
    signer = testing_servers.remote_primitive(lang, private_keyset,
                                              jwt.JwtPublicKeySign)

    now = datetime.datetime.now(tz=datetime.timezone.utc)
    raw_jwt = jwt.new_raw_jwt(
        issuer='issuer',
        expiration=now + datetime.timedelta(seconds=100))
    token = signer.sign_and_encode(raw_jwt)

    private_keyset_without_primary = unset_primary(private_keyset)
    public_keyset_without_primary = unset_primary(public_keyset)

    with self.assertRaises(tink.TinkError):
      _ = testing_servers.remote_primitive(
          lang, private_keyset_without_primary, jwt.JwtPublicKeySign)

    if lang not in ['cc', 'java', 'python']:
      with self.assertRaises(tink.TinkError):
        _ = testing_servers.remote_primitive(lang,
                                             public_keyset_without_primary,
                                             jwt.JwtPublicKeyVerify)
    if lang in ['cc', 'java', 'python']:
      # TODO(b/252792776) This should fail.
      verifier_without_primary = testing_servers.remote_primitive(
          lang, public_keyset_without_primary, jwt.JwtPublicKeyVerify)
      validator = jwt.new_validator(expected_issuer='issuer', fixed_now=now)
      verifier_without_primary.verify_and_decode(token, validator)

  @parameterized.parameters(test_cases(jwt.JwtMac))
  def test_jwt_mac_without_primary(self, key_template_name, lang):
    """Unsets the primary key and tries to create and verify JWT MACs."""
    template = utilities.KEY_TEMPLATE[key_template_name]
    keyset = testing_servers.new_keyset(lang, template)

    with self.assertRaises(tink.TinkError):
      _ = testing_servers.remote_primitive(lang, unset_primary(keyset),
                                           jwt.JwtMac)


if __name__ == '__main__':
  absltest.main()
