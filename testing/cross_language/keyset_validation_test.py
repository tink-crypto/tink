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
      for lang in tink_config.SUPPORTED_LANGUAGES[key_type]:
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
      _ = testing_servers.deterministic_aead(lang, unset_primary(keyset))

  @parameterized.parameters(test_cases(mac.Mac))
  def test_mac_without_primary(self, key_template_name, lang):
    """Unsets the primary key and tries to use a MAC primitive."""
    template = utilities.KEY_TEMPLATE[key_template_name]
    keyset = testing_servers.new_keyset(lang, template)
    mac_value = testing_servers.mac(lang, keyset).compute_mac(b'foo')
    mac_without_primary = testing_servers.mac(lang, unset_primary(keyset))
    with self.assertRaises(tink.TinkError):
      _ = mac_without_primary.compute_mac(b'foo')
    with self.assertRaises(tink.TinkError):
      mac_without_primary.verify_mac(mac_value, b'foo')

  @parameterized.parameters(test_cases(prf.PrfSet))
  def test_prf_without_primary(self, key_template_name, lang):
    """Unsets the primary key and tries to use a PRF set primitive."""
    template = utilities.KEY_TEMPLATE[key_template_name]
    keyset = testing_servers.new_keyset(lang, template)
    _ = testing_servers.prf_set(lang, keyset).primary().compute(b'foo', 16)
    prf_set_without_primary = testing_servers.prf_set(lang,
                                                      unset_primary(keyset))
    with self.assertRaises(tink.TinkError):
      _ = prf_set_without_primary.primary().compute(b'foo', 16)

  @parameterized.parameters(test_cases(signature.PublicKeySign))
  def test_signature_without_primary(self, key_template_name, lang):
    """Unsets the primary key and tries to sign and verify signatures."""
    template = utilities.KEY_TEMPLATE[key_template_name]
    private_keyset = testing_servers.new_keyset(lang, template)
    public_keyset = testing_servers.public_keyset(lang, private_keyset)
    sig = testing_servers.public_key_sign(lang, private_keyset).sign(b'foo')
    testing_servers.public_key_verify(lang, public_keyset).verify(sig, b'foo')

    signer_without_primary = testing_servers.public_key_sign(
        lang, unset_primary(private_keyset))
    verifier_without_primary = testing_servers.public_key_verify(
        lang, unset_primary(public_keyset))
    with self.assertRaises(tink.TinkError):
      signer_without_primary.sign(b'foo')
    if lang in ['java', 'python']:
      # Java and Python currently allow this.
      verifier_without_primary.verify(sig, b'foo')
    else:
      with self.assertRaises(tink.TinkError):
        verifier_without_primary.verify(sig, b'foo')

  @parameterized.parameters(test_cases(hybrid.HybridDecrypt))
  def test_hybrid_without_primary(self, key_template_name, lang):
    """Unsets the primary key and tries to use hybrid encryption."""
    template = utilities.KEY_TEMPLATE[key_template_name]
    private_keyset = testing_servers.new_keyset(lang, template)
    public_keyset = testing_servers.public_keyset(lang, private_keyset)
    ciphertext = testing_servers.hybrid_encrypt(lang, public_keyset).encrypt(
        b'foo', b'context_info')

    dec_without_primary = testing_servers.hybrid_decrypt(
        lang, unset_primary(private_keyset))
    with self.assertRaises(tink.TinkError):
      dec_without_primary.decrypt(ciphertext, b'context_info')

    enc_without_primary = testing_servers.hybrid_encrypt(
        lang, unset_primary(public_keyset))
    with self.assertRaises(tink.TinkError):
      enc_without_primary.encrypt(b'foo', b'context_info')

  @parameterized.parameters(test_cases(jwt.JwtPublicKeySign))
  def test_jwt_signature_without_primary(self, key_template_name, lang):
    """Unsets the primary key and tries to sign and verify JWT signatures."""
    template = utilities.KEY_TEMPLATE[key_template_name]
    private_keyset = testing_servers.new_keyset(lang, template)
    public_keyset = testing_servers.public_keyset(lang, private_keyset)
    signer = testing_servers.jwt_public_key_sign(lang, private_keyset)

    now = datetime.datetime.now(tz=datetime.timezone.utc)
    raw_jwt = jwt.new_raw_jwt(
        issuer='issuer',
        expiration=now + datetime.timedelta(seconds=100))
    token = signer.sign_and_encode(raw_jwt)

    signer_without_primary = testing_servers.jwt_public_key_sign(
        lang, unset_primary(private_keyset))
    with self.assertRaises(tink.TinkError):
      signer_without_primary.sign_and_encode(raw_jwt)

    verifier_without_primary = testing_servers.jwt_public_key_verify(
        lang, unset_primary(public_keyset))
    validator = jwt.new_validator(expected_issuer='issuer', fixed_now=now)
    if lang in ['cc', 'java', 'python']:
      # C++, Java and Python currently allow this.
      verifier_without_primary.verify_and_decode(token, validator)
    else:
      with self.assertRaises(tink.TinkError):
        verifier_without_primary.verify_and_decode(token, validator)

  @parameterized.parameters(test_cases(jwt.JwtMac))
  def test_jwt_mac_without_primary(self, key_template_name, lang):
    """Unsets the primary key and tries to create and verify JWT MACs."""
    template = utilities.KEY_TEMPLATE[key_template_name]
    keyset = testing_servers.new_keyset(lang, template)
    jwt_mac = testing_servers.jwt_mac(lang, keyset)

    now = datetime.datetime.now(tz=datetime.timezone.utc)
    raw_jwt = jwt.new_raw_jwt(
        issuer='issuer',
        expiration=now + datetime.timedelta(seconds=100))
    token = jwt_mac.compute_mac_and_encode(raw_jwt)

    jwt_mac_without_primary = testing_servers.jwt_mac(
        lang, unset_primary(keyset))
    with self.assertRaises(tink.TinkError):
      jwt_mac_without_primary.compute_mac_and_encode(raw_jwt)

    validator = jwt.new_validator(expected_issuer='issuer', fixed_now=now)
    with self.assertRaises(tink.TinkError):
      jwt_mac_without_primary.verify_mac_and_decode(token, validator)


if __name__ == '__main__':
  absltest.main()
