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
"""Tests for tink.python.tink.jwt._jwt_mac_wrapper."""

from absl.testing import absltest
from absl.testing import parameterized

from tink.proto import jwt_hmac_pb2
from tink.proto import tink_pb2
import tink
from tink import jwt
from tink.jwt import _jwt_format
from tink.testing import keyset_builder


def setUpModule():
  jwt.register_jwt_mac()


def _create_jwt_hmac_template(
    algorithm: jwt_hmac_pb2.JwtHmacAlgorithm, key_size: int,
    output_prefix_type: tink_pb2.OutputPrefixType) -> tink_pb2.KeyTemplate:
  key_format = jwt_hmac_pb2.JwtHmacKeyFormat(
      algorithm=algorithm, key_size=key_size)
  return tink_pb2.KeyTemplate(
      type_url='type.googleapis.com/google.crypto.tink.JwtHmacKey',
      value=key_format.SerializeToString(),
      output_prefix_type=output_prefix_type)


def jwt_hs256_tink_template() -> tink_pb2.KeyTemplate:
  return _create_jwt_hmac_template(jwt_hmac_pb2.HS256, 32, tink_pb2.TINK)


class JwtMacWrapperTest(parameterized.TestCase):

  @parameterized.parameters([
      (jwt.jwt_hs256_template(), jwt.jwt_hs256_template()),
      (jwt.jwt_hs256_template(), jwt_hs256_tink_template()),
      (jwt_hs256_tink_template(), jwt.jwt_hs256_template()),
      (jwt_hs256_tink_template(), jwt_hs256_tink_template()),
  ])
  def test_key_rotation(self, old_key_tmpl, new_key_tmpl):
    builder = keyset_builder.new_keyset_builder()
    older_key_id = builder.add_new_key(old_key_tmpl)

    builder.set_primary_key(older_key_id)
    jwtmac1 = builder.keyset_handle().primitive(jwt.JwtMac)

    newer_key_id = builder.add_new_key(new_key_tmpl)
    jwtmac2 = builder.keyset_handle().primitive(jwt.JwtMac)

    builder.set_primary_key(newer_key_id)
    jwtmac3 = builder.keyset_handle().primitive(jwt.JwtMac)

    builder.disable_key(older_key_id)
    jwtmac4 = builder.keyset_handle().primitive(jwt.JwtMac)

    raw_jwt = jwt.new_raw_jwt(issuer='a', without_expiration=True)
    validator = jwt.new_validator(
        expected_issuer='a', allow_missing_expiration=True)

    self.assertNotEqual(older_key_id, newer_key_id)
    # 1 uses the older key. So 1, 2 and 3 can verify the mac, but not 4.
    compact1 = jwtmac1.compute_mac_and_encode(raw_jwt)
    self.assertEqual(
        jwtmac1.verify_mac_and_decode(compact1, validator).issuer(), 'a')
    self.assertEqual(
        jwtmac2.verify_mac_and_decode(compact1, validator).issuer(), 'a')
    self.assertEqual(
        jwtmac3.verify_mac_and_decode(compact1, validator).issuer(), 'a')
    with self.assertRaises(tink.TinkError):
      jwtmac4.verify_mac_and_decode(compact1, validator)

    # 2 uses the older key. So 1, 2 and 3 can verify the mac, but not 4.
    compact2 = jwtmac2.compute_mac_and_encode(raw_jwt)
    self.assertEqual(
        jwtmac1.verify_mac_and_decode(compact2, validator).issuer(), 'a')
    self.assertEqual(
        jwtmac2.verify_mac_and_decode(compact2, validator).issuer(), 'a')
    self.assertEqual(
        jwtmac3.verify_mac_and_decode(compact2, validator).issuer(), 'a')
    with self.assertRaises(tink.TinkError):
      jwtmac4.verify_mac_and_decode(compact2, validator)

    # 3 uses the newer key. So 2, 3 and 4 can verify the mac, but not 1.
    compact3 = jwtmac3.compute_mac_and_encode(raw_jwt)
    with self.assertRaises(tink.TinkError):
      jwtmac1.verify_mac_and_decode(compact3, validator)
    self.assertEqual(
        jwtmac2.verify_mac_and_decode(compact3, validator).issuer(), 'a')
    self.assertEqual(
        jwtmac3.verify_mac_and_decode(compact3, validator).issuer(), 'a')
    self.assertEqual(
        jwtmac4.verify_mac_and_decode(compact3, validator).issuer(), 'a')

    # 4 uses the newer key. So 2, 3 and 4 can verify the mac, but not 1.
    compact4 = jwtmac4.compute_mac_and_encode(raw_jwt)
    with self.assertRaises(tink.TinkError):
      jwtmac1.verify_mac_and_decode(compact4, validator)
    self.assertEqual(
        jwtmac2.verify_mac_and_decode(compact4, validator).issuer(), 'a')
    self.assertEqual(
        jwtmac3.verify_mac_and_decode(compact4, validator).issuer(), 'a')
    self.assertEqual(
        jwtmac4.verify_mac_and_decode(compact4, validator).issuer(), 'a')

  def test_tink_output_prefix_type_encodes_a_kid_header(self):
    keyset_handle = tink.new_keyset_handle(jwt_hs256_tink_template())
    jwt_mac = keyset_handle.primitive(jwt.JwtMac)

    raw_jwt = jwt.new_raw_jwt(issuer='issuer', without_expiration=True)
    signed_compact = jwt_mac.compute_mac_and_encode(raw_jwt)

    _, json_header, _, _ = _jwt_format.split_signed_compact(signed_compact)
    header = _jwt_format.json_loads(json_header)
    self.assertIn('kid', header)

  def test_raw_output_prefix_type_encodes_a_custom_kid_header(self):
    keyset_handle = tink.new_keyset_handle(jwt.raw_jwt_hs256_template())

    # Add a custom kid to the key in keyset_handle
    value = keyset_handle._keyset.key[0].key_data.value
    hmac_key = jwt_hmac_pb2.JwtHmacKey.FromString(value)
    hmac_key.custom_kid.value = 'my kid'
    keyset_handle._keyset.key[0].key_data.value = hmac_key.SerializeToString()

    jwt_mac = keyset_handle.primitive(jwt.JwtMac)

    raw_jwt = jwt.new_raw_jwt(issuer='issuer', without_expiration=True)
    signed_compact = jwt_mac.compute_mac_and_encode(raw_jwt)

    _, json_header, _, _ = _jwt_format.split_signed_compact(signed_compact)
    header = _jwt_format.json_loads(json_header)
    self.assertEqual(header['kid'], 'my kid')

    # Now, change the output prefix type to TINK. This should fail.
    keyset_handle._keyset.key[0].output_prefix_type = tink_pb2.TINK
    with self.assertRaises(tink.TinkError):
      tink_jwt_mac = keyset_handle.primitive(jwt.JwtMac)
      tink_jwt_mac.compute_mac_and_encode(raw_jwt)

  def test_legacy_key_fails(self):
    template = _create_jwt_hmac_template(jwt_hmac_pb2.HS256, 32,
                                         tink_pb2.LEGACY)
    builder = keyset_builder.new_keyset_builder()
    key_id = builder.add_new_key(template)
    builder.set_primary_key(key_id)
    handle = builder.keyset_handle()
    with self.assertRaises(tink.TinkError):
      handle.primitive(jwt.JwtMac)

  def test_legacy_non_primary_key_fails(self):
    builder = keyset_builder.new_keyset_builder()
    old_template = _create_jwt_hmac_template(jwt_hmac_pb2.HS256, 32,
                                             tink_pb2.LEGACY)
    _ = builder.add_new_key(old_template)
    current_key_id = builder.add_new_key(jwt.jwt_hs256_template())
    builder.set_primary_key(current_key_id)
    handle = builder.keyset_handle()
    with self.assertRaises(tink.TinkError):
      handle.primitive(jwt.JwtMac)

if __name__ == '__main__':
  absltest.main()
