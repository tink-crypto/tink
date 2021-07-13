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
from tink.jwt import _jwt_format
from tink.testing import keyset_builder


def setUpModule():
  jwt.register_jwt_signature()


def _create_jwt_ecdsa_template(
    algorithm: jwt_ecdsa_pb2.JwtEcdsaAlgorithm,
    output_prefix_type: tink_pb2.OutputPrefixType) -> tink_pb2.KeyTemplate:
  key_format = jwt_ecdsa_pb2.JwtEcdsaKeyFormat(algorithm=algorithm)
  return tink_pb2.KeyTemplate(
      type_url='type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey',
      value=key_format.SerializeToString(),
      output_prefix_type=output_prefix_type)


def jwt_es256_tink_template():
  return _create_jwt_ecdsa_template(jwt_ecdsa_pb2.ES256, tink_pb2.TINK)


class JwtSignatureWrapperTest(parameterized.TestCase):

  # TODO(juerg): Add tests with TINK templates

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
      (jwt.jwt_es256_template(), jwt.jwt_es256_template()),
      (jwt.jwt_es256_template(), jwt_es256_tink_template()),
      (jwt_es256_tink_template, jwt.jwt_es256_template()),
      (jwt_es256_tink_template(), jwt_es256_tink_template()),
  ])
  def test_key_rotation(self, old_key_tmpl, new_key_tmpl):
    old_key_tmpl = jwt.jwt_es256_template()
    new_key_tmpl = jwt.jwt_es384_template()
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

  def test_tink_output_prefix_type_encodes_a_kid_header(self):
    keyset_handle = tink.new_keyset_handle(jwt_es256_tink_template())
    sign = keyset_handle.primitive(jwt.JwtPublicKeySign)

    raw_jwt = jwt.new_raw_jwt(issuer='issuer', without_expiration=True)
    signed_compact = sign.sign_and_encode(raw_jwt)

    _, json_header, _, _ = _jwt_format.split_signed_compact(signed_compact)
    header = _jwt_format.json_loads(json_header)
    self.assertIn('kid', header)

  def test_es256_key_with_custom_kid_header(self):
    keyset_handle = tink.new_keyset_handle(jwt.raw_jwt_es256_template())

    # Add a custom kid to the key in keyset_handle
    value = keyset_handle._keyset.key[0].key_data.value
    ecdsa_key = jwt_ecdsa_pb2.JwtEcdsaPrivateKey.FromString(value)
    ecdsa_key.public_key.custom_kid.value = 'my kid'
    keyset_handle._keyset.key[0].key_data.value = ecdsa_key.SerializeToString()
    sign = keyset_handle.primitive(jwt.JwtPublicKeySign)

    raw_jwt = jwt.new_raw_jwt(issuer='issuer', without_expiration=True)
    signed_compact = sign.sign_and_encode(raw_jwt)

    _, json_header, _, _ = _jwt_format.split_signed_compact(signed_compact)
    header = _jwt_format.json_loads(json_header)
    self.assertEqual(header['kid'], 'my kid')

    # Now, change the output prefix type to TINK. This should fail.
    keyset_handle._keyset.key[0].output_prefix_type = tink_pb2.TINK
    with self.assertRaises(tink.TinkError):
      tink_sign = keyset_handle.primitive(jwt.JwtPublicKeySign)
      tink_sign.sign_and_encode(raw_jwt)

  def test_rs256_key_with_custom_kid_header(self):
    keyset_handle = tink.new_keyset_handle(jwt.raw_jwt_rs256_2048_f4_template())

    # Add a custom kid to the key in keyset_handle
    value = keyset_handle._keyset.key[0].key_data.value
    pkcs1_key = jwt_rsa_ssa_pkcs1_pb2.JwtRsaSsaPkcs1PrivateKey.FromString(value)
    pkcs1_key.public_key.custom_kid.value = 'my kid'
    keyset_handle._keyset.key[0].key_data.value = pkcs1_key.SerializeToString()

    sign = keyset_handle.primitive(jwt.JwtPublicKeySign)

    raw_jwt = jwt.new_raw_jwt(issuer='issuer', without_expiration=True)
    signed_compact = sign.sign_and_encode(raw_jwt)

    _, json_header, _, _ = _jwt_format.split_signed_compact(signed_compact)
    header = _jwt_format.json_loads(json_header)
    self.assertEqual(header['kid'], 'my kid')

    # Now, change the output prefix type to TINK. This should fail.
    keyset_handle._keyset.key[0].output_prefix_type = tink_pb2.TINK
    with self.assertRaises(tink.TinkError):
      tink_sign = keyset_handle.primitive(jwt.JwtPublicKeySign)
      tink_sign.sign_and_encode(raw_jwt)

  def test_ps256_key_with_a_custom_kid_header(self):
    keyset_handle = tink.new_keyset_handle(jwt.raw_jwt_ps256_2048_f4_template())

    # Add a custom kid to the key in keyset_handle
    value = keyset_handle._keyset.key[0].key_data.value
    pss_key = jwt_rsa_ssa_pss_pb2.JwtRsaSsaPssPrivateKey.FromString(value)
    pss_key.public_key.custom_kid.value = 'my kid'
    keyset_handle._keyset.key[0].key_data.value = pss_key.SerializeToString()

    sign = keyset_handle.primitive(jwt.JwtPublicKeySign)

    raw_jwt = jwt.new_raw_jwt(issuer='issuer', without_expiration=True)
    signed_compact = sign.sign_and_encode(raw_jwt)

    _, json_header, _, _ = _jwt_format.split_signed_compact(signed_compact)
    header = _jwt_format.json_loads(json_header)
    self.assertEqual(header['kid'], 'my kid')

    # Now, change the output prefix type to TINK. This should fail.
    keyset_handle._keyset.key[0].output_prefix_type = tink_pb2.TINK
    with self.assertRaises(tink.TinkError):
      tink_sign = keyset_handle.primitive(jwt.JwtPublicKeySign)
      tink_sign.sign_and_encode(raw_jwt)

  def test_legacy_template_fails(self):
    template = _create_jwt_ecdsa_template(jwt_ecdsa_pb2.ES256, tink_pb2.LEGACY)
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
    old_template = _create_jwt_ecdsa_template(jwt_ecdsa_pb2.ES256,
                                              tink_pb2.LEGACY)
    _ = builder.add_new_key(old_template)
    current_key_id = builder.add_new_key(jwt.jwt_es256_template())
    builder.set_primary_key(current_key_id)
    handle = builder.keyset_handle()
    with self.assertRaises(tink.TinkError):
      handle.primitive(jwt.JwtPublicKeySign)
    with self.assertRaises(tink.TinkError):
      handle.public_keyset_handle().primitive(jwt.JwtPublicKeyVerify)

if __name__ == '__main__':
  absltest.main()
