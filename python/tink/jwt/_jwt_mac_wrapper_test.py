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
from tink import secret_key_access
from tink.jwt import _json_util
from tink.jwt import _jwt_format
from tink.testing import keyset_builder


def setUpModule():
  jwt.register_jwt_mac()


def _set_custom_kid(keyset_handle: tink.KeysetHandle,
                    custom_kid: str) -> tink.KeysetHandle:
  """Set the custom_kid field of the first key."""
  serialized_keyset = tink.proto_keyset_format.serialize(
      keyset_handle, secret_key_access.TOKEN
  )
  keyset = tink_pb2.Keyset.FromString(serialized_keyset)
  hmac_key = jwt_hmac_pb2.JwtHmacKey.FromString(keyset.key[0].key_data.value)
  hmac_key.custom_kid.value = custom_kid
  keyset.key[0].key_data.value = hmac_key.SerializeToString()
  return tink.proto_keyset_format.parse(
      keyset.SerializeToString(), secret_key_access.TOKEN
  )


def _change_key_id(keyset_handle: tink.KeysetHandle) -> tink.KeysetHandle:
  """Changes the key id of the first key and sets it primary."""
  serialized_keyset = tink.proto_keyset_format.serialize(
      keyset_handle, secret_key_access.TOKEN
  )
  keyset = tink_pb2.Keyset.FromString(serialized_keyset)
  # XOR the key id with an arbitrary 32-bit string to get a new key id.
  new_key_id = keyset.key[0].key_id ^ 0xdeadbeef
  keyset.key[0].key_id = new_key_id
  keyset.primary_key_id = new_key_id
  return tink.proto_keyset_format.parse(
      keyset.SerializeToString(), secret_key_access.TOKEN
  )


def _change_output_prefix_to_tink(
    keyset_handle: tink.KeysetHandle) -> tink.KeysetHandle:
  """Changes the output prefix type of the first key to TINK."""
  serialization = tink.proto_keyset_format.serialize(
      keyset_handle, secret_key_access.TOKEN
  )
  keyset = tink_pb2.Keyset.FromString(serialization)
  keyset.key[0].output_prefix_type = tink_pb2.TINK
  return tink.proto_keyset_format.parse(
      keyset.SerializeToString(), secret_key_access.TOKEN
  )


class JwtMacWrapperTest(parameterized.TestCase):

  @parameterized.parameters([
      (jwt.raw_jwt_hs256_template(), jwt.raw_jwt_hs256_template()),
      (jwt.raw_jwt_hs256_template(), jwt.jwt_hs256_template()),
      (jwt.jwt_hs256_template(), jwt.raw_jwt_hs256_template()),
      (jwt.jwt_hs256_template(), jwt.jwt_hs256_template()),
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

  def test_only_tink_output_prefix_type_encodes_a_kid_header(self):
    handle = tink.new_keyset_handle(jwt.raw_jwt_hs256_template())
    jwt_mac = handle.primitive(jwt.JwtMac)

    tink_handle = _change_output_prefix_to_tink(handle)
    tink_jwt_mac = tink_handle.primitive(jwt.JwtMac)

    raw_jwt = jwt.new_raw_jwt(issuer='issuer', without_expiration=True)

    token = jwt_mac.compute_mac_and_encode(raw_jwt)
    token_with_kid = tink_jwt_mac.compute_mac_and_encode(raw_jwt)

    _, header, _, _ = _jwt_format.split_signed_compact(token)
    self.assertNotIn('kid', _json_util.json_loads(header))

    _, header_with_kid, _, _ = _jwt_format.split_signed_compact(token_with_kid)
    self.assertIn('kid', _json_util.json_loads(header_with_kid))

    validator = jwt.new_validator(
        expected_issuer='issuer', allow_missing_expiration=True)
    jwt_mac.verify_mac_and_decode(token, validator)
    tink_jwt_mac.verify_mac_and_decode(token_with_kid, validator)

    # With output prefix type RAW, a kid header is ignored
    jwt_mac.verify_mac_and_decode(token_with_kid, validator)
    # With output prefix type TINK, a kid header is required.
    with self.assertRaises(tink.TinkError):
      tink_jwt_mac.verify_mac_and_decode(token, validator)

    other_handle = _change_key_id(tink_handle)
    other_jwt_mac = other_handle.primitive(jwt.JwtMac)
    # A token with a wrong kid is rejected, even if the signature is ok.
    with self.assertRaises(tink.TinkError):
      other_jwt_mac.verify_mac_and_decode(token_with_kid, validator)

  def test_raw_output_prefix_type_encodes_a_custom_kid_header(self):
    # normal HMAC jwt_mac with output prefix RAW
    handle = tink.new_keyset_handle(jwt.raw_jwt_hs256_template())
    raw_jwt = jwt.new_raw_jwt(issuer='issuer', without_expiration=True)
    validator = jwt.new_validator(
        expected_issuer='issuer', allow_missing_expiration=True)

    jwt_mac = handle.primitive(jwt.JwtMac)
    token = jwt_mac.compute_mac_and_encode(raw_jwt)
    jwt_mac.verify_mac_and_decode(token, validator)

    _, json_header, _, _ = _jwt_format.split_signed_compact(token)
    self.assertNotIn('kid', _json_util.json_loads(json_header))

    # HMAC jwt_mac with a custom_kid set
    custom_kid_handle = _set_custom_kid(handle, custom_kid='my kid')
    custom_kid_jwt_mac = custom_kid_handle.primitive(jwt.JwtMac)
    token_with_kid = custom_kid_jwt_mac.compute_mac_and_encode(raw_jwt)
    custom_kid_jwt_mac.verify_mac_and_decode(token_with_kid, validator)

    _, header_with_kid, _, _ = _jwt_format.split_signed_compact(token_with_kid)
    self.assertEqual(_json_util.json_loads(header_with_kid)['kid'], 'my kid')

    # Even when custom_kid is set, its not required to be set in the header.
    custom_kid_jwt_mac.verify_mac_and_decode(token, validator)
    # An additional kid header is ignored.
    jwt_mac.verify_mac_and_decode(token_with_kid, validator)

    other_handle = _set_custom_kid(handle, custom_kid='other kid')
    other_jwt_mac = other_handle.primitive(jwt.JwtMac)
    with self.assertRaises(tink.TinkError):
      # The custom_kid does not match the kid header.
      other_jwt_mac.verify_mac_and_decode(
          token_with_kid, validator)

    tink_handle = _change_output_prefix_to_tink(custom_kid_handle)
    tink_jwt_mac = tink_handle.primitive(jwt.JwtMac)
    # having custom_kid set with output prefix TINK is not allowed
    with self.assertRaises(tink.TinkError):
      tink_jwt_mac.compute_mac_and_encode(raw_jwt)
    with self.assertRaises(tink.TinkError):
      tink_jwt_mac.verify_mac_and_decode(token, validator)
    with self.assertRaises(tink.TinkError):
      tink_jwt_mac.verify_mac_and_decode(token_with_kid, validator)

  def test_legacy_key_fails(self):
    template = keyset_builder.legacy_template(jwt.raw_jwt_hs256_template())
    builder = keyset_builder.new_keyset_builder()
    key_id = builder.add_new_key(template)
    builder.set_primary_key(key_id)
    handle = builder.keyset_handle()
    with self.assertRaises(tink.TinkError):
      handle.primitive(jwt.JwtMac)

  def test_legacy_non_primary_key_fails(self):
    builder = keyset_builder.new_keyset_builder()
    old_template = keyset_builder.legacy_template(jwt.raw_jwt_hs256_template())
    _ = builder.add_new_key(old_template)
    current_key_id = builder.add_new_key(jwt.jwt_hs256_template())
    builder.set_primary_key(current_key_id)
    handle = builder.keyset_handle()
    with self.assertRaises(tink.TinkError):
      handle.primitive(jwt.JwtMac)

  def test_jwt_mac_from_keyset_without_primary_fails(self):
    builder = keyset_builder.new_keyset_builder()
    builder.add_new_key(jwt.raw_jwt_hs256_template())
    with self.assertRaises(tink.TinkError):
      builder.keyset_handle()


if __name__ == '__main__':
  absltest.main()
