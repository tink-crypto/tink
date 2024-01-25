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
"""Tests for tink.python.tink.jwt._jwt_signature_wrappers_test."""

from absl.testing import absltest
from absl.testing import parameterized

from tink.proto import jwt_ecdsa_pb2
from tink.proto import jwt_rsa_ssa_pkcs1_pb2
from tink.proto import jwt_rsa_ssa_pss_pb2
from tink.proto import tink_pb2
import tink
from tink import jwt
from tink import secret_key_access
from tink.jwt import _json_util
from tink.jwt import _jwt_format
from tink.testing import keyset_builder


LONG_CUSTOM_KID = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit'


def setUpModule():
  jwt.register_jwt_signature()


def _change_key_id(keyset_handle: tink.KeysetHandle) -> tink.KeysetHandle:
  """Changes the key id of the first key and makes it primary."""
  serialization = tink.proto_keyset_format.serialize(
      keyset_handle, secret_key_access.TOKEN
  )
  keyset = tink_pb2.Keyset.FromString(serialization)
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


def _set_custom_kid(keyset_handle: tink.KeysetHandle,
                    custom_kid: str) -> tink.KeysetHandle:
  """Sets the custom_kid field of the first key."""
  serialization = tink.proto_keyset_format.serialize(
      keyset_handle, secret_key_access.TOKEN
  )
  keyset = tink_pb2.Keyset.FromString(serialization)
  if keyset.key[0].key_data.type_url.endswith('JwtEcdsaPrivateKey'):
    jwt_ecdsa_key = jwt_ecdsa_pb2.JwtEcdsaPrivateKey.FromString(
        keyset.key[0].key_data.value)
    jwt_ecdsa_key.public_key.custom_kid.value = custom_kid
    keyset.key[0].key_data.value = jwt_ecdsa_key.SerializeToString()
  elif keyset.key[0].key_data.type_url.endswith('JwtRsaSsaPkcs1PrivateKey'):
    rsa_pkcs1_key = jwt_rsa_ssa_pkcs1_pb2.JwtRsaSsaPkcs1PrivateKey.FromString(
        keyset.key[0].key_data.value
    )
    rsa_pkcs1_key.public_key.custom_kid.value = custom_kid
    keyset.key[0].key_data.value = rsa_pkcs1_key.SerializeToString()
  elif keyset.key[0].key_data.type_url.endswith('JwtRsaSsaPssPrivateKey'):
    rsa_pss_key = jwt_rsa_ssa_pss_pb2.JwtRsaSsaPssPrivateKey.FromString(
        keyset.key[0].key_data.value
    )
    rsa_pss_key.public_key.custom_kid.value = custom_kid
    keyset.key[0].key_data.value = rsa_pss_key.SerializeToString()
  else:
    raise tink.TinkError('unknown key type')
  return tink.proto_keyset_format.parse(
      keyset.SerializeToString(), secret_key_access.TOKEN
  )


class JwtSignatureWrapperTest(parameterized.TestCase):

  def test_interesting_error(self):
    private_handle = tink.new_keyset_handle(jwt.jwt_es256_template())
    sign = private_handle.primitive(jwt.JwtPublicKeySign)
    verify = private_handle.public_keyset_handle().primitive(
        jwt.JwtPublicKeyVerify)
    raw_jwt = jwt.new_raw_jwt(issuer='issuer', without_expiration=True)
    compact = sign.sign_and_encode(raw_jwt)
    with self.assertRaisesRegex(jwt.JwtInvalidError,
                                'invalid JWT; expected issuer'):
      verify.verify_and_decode(compact, jwt.new_validator(
          expected_issuer='unknown', allow_missing_expiration=True))

  @parameterized.parameters([
      (jwt.raw_jwt_es256_template(), jwt.raw_jwt_es256_template()),
      (jwt.raw_jwt_es256_template(), jwt.jwt_es256_template()),
      (jwt.jwt_es256_template(), jwt.raw_jwt_es256_template()),
      (jwt.jwt_es256_template(), jwt.jwt_es256_template()),
  ])
  def test_key_rotation(self, old_key_tmpl, new_key_tmpl):
    builder = keyset_builder.new_keyset_builder()
    older_key_id = builder.add_new_key(old_key_tmpl)

    builder.set_primary_key(older_key_id)
    handle1 = builder.keyset_handle()
    sign1 = handle1.primitive(jwt.JwtPublicKeySign)
    verify1 = handle1.public_keyset_handle().primitive(jwt.JwtPublicKeyVerify)

    newer_key_id = builder.add_new_key(new_key_tmpl)
    handle2 = builder.keyset_handle()
    sign2 = handle2.primitive(jwt.JwtPublicKeySign)
    verify2 = handle2.public_keyset_handle().primitive(jwt.JwtPublicKeyVerify)

    builder.set_primary_key(newer_key_id)
    handle3 = builder.keyset_handle()
    sign3 = handle3.primitive(jwt.JwtPublicKeySign)
    verify3 = handle3.public_keyset_handle().primitive(jwt.JwtPublicKeyVerify)

    builder.disable_key(older_key_id)
    handle4 = builder.keyset_handle()
    sign4 = handle4.primitive(jwt.JwtPublicKeySign)
    verify4 = handle4.public_keyset_handle().primitive(jwt.JwtPublicKeyVerify)

    raw_jwt = jwt.new_raw_jwt(issuer='a', without_expiration=True)
    validator = jwt.new_validator(
        expected_issuer='a', allow_missing_expiration=True)

    self.assertNotEqual(older_key_id, newer_key_id)
    # 1 uses the older key. So 1, 2 and 3 can verify the signature, but not 4.
    compact1 = sign1.sign_and_encode(raw_jwt)
    self.assertEqual(
        verify1.verify_and_decode(compact1, validator).issuer(), 'a')
    self.assertEqual(
        verify2.verify_and_decode(compact1, validator).issuer(), 'a')
    self.assertEqual(
        verify3.verify_and_decode(compact1, validator).issuer(), 'a')
    with self.assertRaises(tink.TinkError):
      verify4.verify_and_decode(compact1, validator)

    # 2 uses the older key. So 1, 2 and 3 can verify the signature, but not 4.
    compact2 = sign2.sign_and_encode(raw_jwt)
    self.assertEqual(
        verify1.verify_and_decode(compact2, validator).issuer(), 'a')
    self.assertEqual(
        verify2.verify_and_decode(compact2, validator).issuer(), 'a')
    self.assertEqual(
        verify3.verify_and_decode(compact2, validator).issuer(), 'a')
    with self.assertRaises(tink.TinkError):
      verify4.verify_and_decode(compact2, validator)

    # 3 uses the newer key. So 2, 3 and 4 can verify the signature, but not 1.
    compact3 = sign3.sign_and_encode(raw_jwt)
    with self.assertRaises(tink.TinkError):
      verify1.verify_and_decode(compact3, validator)
    self.assertEqual(
        verify2.verify_and_decode(compact3, validator).issuer(), 'a')
    self.assertEqual(
        verify3.verify_and_decode(compact3, validator).issuer(), 'a')
    self.assertEqual(
        verify4.verify_and_decode(compact3, validator).issuer(), 'a')

    # 4 uses the newer key. So 2, 3 and 4 can verify the signature, but not 1.
    compact4 = sign4.sign_and_encode(raw_jwt)
    with self.assertRaises(tink.TinkError):
      verify1.verify_and_decode(compact4, validator)
    self.assertEqual(
        verify2.verify_and_decode(compact4, validator).issuer(), 'a')
    self.assertEqual(
        verify3.verify_and_decode(compact4, validator).issuer(), 'a')
    self.assertEqual(
        verify4.verify_and_decode(compact4, validator).issuer(), 'a')

  def test_only_tink_output_prefix_type_encodes_a_kid_header(self):
    handle = tink.new_keyset_handle(jwt.raw_jwt_es256_template())
    sign = handle.primitive(jwt.JwtPublicKeySign)
    verify = handle.public_keyset_handle().primitive(jwt.JwtPublicKeyVerify)

    tink_handle = _change_output_prefix_to_tink(handle)
    tink_sign = tink_handle.primitive(jwt.JwtPublicKeySign)
    tink_verify = tink_handle.public_keyset_handle().primitive(
        jwt.JwtPublicKeyVerify)

    raw_jwt = jwt.new_raw_jwt(issuer='issuer', without_expiration=True)

    token = sign.sign_and_encode(raw_jwt)
    token_with_kid = tink_sign.sign_and_encode(raw_jwt)

    _, header, _, _ = _jwt_format.split_signed_compact(token)
    self.assertNotIn('kid', _json_util.json_loads(header))

    _, header_with_kid, _, _ = _jwt_format.split_signed_compact(token_with_kid)
    self.assertIn('kid', _json_util.json_loads(header_with_kid))

    validator = jwt.new_validator(
        expected_issuer='issuer', allow_missing_expiration=True)

    verify.verify_and_decode(token, validator)
    tink_verify.verify_and_decode(token_with_kid, validator)

    other_handle = _change_key_id(tink_handle)
    other_verify = other_handle.public_keyset_handle().primitive(
        jwt.JwtPublicKeyVerify)

    verify.verify_and_decode(token_with_kid, validator)
    # For output prefix type TINK, the kid header is required.
    with self.assertRaises(tink.TinkError):
      tink_verify.verify_and_decode(token, validator)
    # This should fail because value of the kid header is wrong.
    with self.assertRaises(tink.TinkError):
      other_verify.verify_and_decode(token_with_kid, validator)

  @parameterized.named_parameters([
      ('JWT_ES256_RAW', jwt.raw_jwt_es256_template()),
      ('JWT_RS256_RAW', jwt.raw_jwt_rs256_2048_f4_template()),
      ('JWT_PS256_RAW', jwt.raw_jwt_ps256_3072_f4_template()),
  ])
  def test_raw_key_with_custom_kid_header(self, template):
    # normal key with output prefix RAW
    handle = tink.new_keyset_handle(template)
    raw_jwt = jwt.new_raw_jwt(issuer='issuer', without_expiration=True)
    validator = jwt.new_validator(
        expected_issuer='issuer', allow_missing_expiration=True)

    sign = handle.primitive(jwt.JwtPublicKeySign)
    token = sign.sign_and_encode(raw_jwt)
    verify = handle.public_keyset_handle().primitive(jwt.JwtPublicKeyVerify)
    verify.verify_and_decode(token, validator)

    _, json_header, _, _ = _jwt_format.split_signed_compact(token)
    self.assertNotIn('kid', _json_util.json_loads(json_header))

    # key with a custom_kid set
    custom_kid_handle = _set_custom_kid(handle, custom_kid=LONG_CUSTOM_KID)
    custom_kid_sign = custom_kid_handle.primitive(jwt.JwtPublicKeySign)
    token_with_kid = custom_kid_sign.sign_and_encode(raw_jwt)
    custom_kid_verify = custom_kid_handle.public_keyset_handle().primitive(
        jwt.JwtPublicKeyVerify)
    custom_kid_verify.verify_and_decode(token_with_kid, validator)

    _, header_with_kid, _, _ = _jwt_format.split_signed_compact(token_with_kid)
    self.assertEqual(_json_util.json_loads(header_with_kid)['kid'],
                     LONG_CUSTOM_KID)

    # The primitive with a custom_kid set accepts tokens without kid header.
    custom_kid_verify.verify_and_decode(token, validator)

    # The primitive without a custom_kid set ignores the kid header.
    verify.verify_and_decode(token_with_kid, validator)

    # key with a different custom_kid set
    other_handle = _set_custom_kid(handle, custom_kid='other kid')
    other_verify = other_handle.public_keyset_handle().primitive(
        jwt.JwtPublicKeyVerify)
    # Fails because the kid value do not match.
    with self.assertRaises(tink.TinkError):
      other_verify.verify_and_decode(token_with_kid, validator)

    tink_handle = _change_output_prefix_to_tink(custom_kid_handle)
    tink_sign = tink_handle.primitive(jwt.JwtPublicKeySign)
    tink_verify = tink_handle.public_keyset_handle().primitive(
        jwt.JwtPublicKeyVerify)
    # Having custom_kid set with output prefix TINK is not allowed.
    with self.assertRaises(tink.TinkError):
      tink_sign.sign_and_encode(raw_jwt)
    with self.assertRaises(tink.TinkError):
      tink_verify.verify_and_decode(token, validator)
    with self.assertRaises(tink.TinkError):
      tink_verify.verify_and_decode(token_with_kid, validator)

  def test_legacy_template_fails(self):
    template = keyset_builder.legacy_template(jwt.jwt_es256_template())
    builder = keyset_builder.new_keyset_builder()
    key_id = builder.add_new_key(template)
    builder.set_primary_key(key_id)
    handle = builder.keyset_handle()
    with self.assertRaises(tink.TinkError):
      handle.primitive(jwt.JwtPublicKeySign)
    with self.assertRaises(tink.TinkError):
      handle.public_keyset_handle().primitive(jwt.JwtPublicKeyVerify)

  def test_legacy_non_primary_key_fails(self):
    builder = keyset_builder.new_keyset_builder()
    old_template = keyset_builder.legacy_template(jwt.jwt_es256_template())
    _ = builder.add_new_key(old_template)
    current_key_id = builder.add_new_key(jwt.jwt_es256_template())
    builder.set_primary_key(current_key_id)
    handle = builder.keyset_handle()
    with self.assertRaises(tink.TinkError):
      handle.primitive(jwt.JwtPublicKeySign)
    with self.assertRaises(tink.TinkError):
      handle.public_keyset_handle().primitive(jwt.JwtPublicKeyVerify)

  def test_jwt_mac_from_keyset_without_primary_fails(self):
    builder = keyset_builder.new_keyset_builder()
    builder.add_new_key(jwt.jwt_es256_template())
    with self.assertRaises(tink.TinkError):
      builder.keyset_handle()


if __name__ == '__main__':
  absltest.main()
