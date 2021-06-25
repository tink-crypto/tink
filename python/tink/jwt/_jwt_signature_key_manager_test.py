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
"""Tests for tink.python.tink.jwt._jwt_signature_key_manager."""

import datetime

from typing import cast, Text

from absl.testing import absltest
from absl.testing import parameterized

from tink.proto import jwt_ecdsa_pb2
from tink.proto import tink_pb2
import tink
from tink import jwt
from tink.jwt import _jwt_format

from tink.jwt import _jwt_signature_key_manager
from tink.jwt import _jwt_signature_wrappers

DATETIME_1970 = datetime.datetime.fromtimestamp(12345, datetime.timezone.utc)
DATETIME_2011 = datetime.datetime.fromtimestamp(1300819380,
                                                datetime.timezone.utc)
DATETIME_2020 = datetime.datetime.fromtimestamp(1582230020,
                                                datetime.timezone.utc)


def setUpModule():
  jwt.register_jwt_signature()


def gen_compact(json_header: Text, json_payload: Text, raw_sign) -> Text:
  unsigned_compact = (
      _jwt_format.encode_header(json_header) + b'.' +
      _jwt_format.encode_payload(json_payload))
  signature = raw_sign.sign(unsigned_compact)
  return _jwt_format.create_signed_compact(unsigned_compact, signature)


class JwtSignatureKeyManagerTest(parameterized.TestCase):

  def test_create_sign_verify(self):
    handle = tink.new_keyset_handle(jwt.jwt_es256_template())
    sign = handle.primitive(jwt.JwtPublicKeySign)
    verify = handle.public_keyset_handle().primitive(jwt.JwtPublicKeyVerify)
    raw_jwt = jwt.new_raw_jwt(
        issuer='joe',
        expiration=DATETIME_2011,
        custom_claims={'http://example.com/is_root': True})
    signed_compact = sign.sign_and_encode(raw_jwt)

    validator = jwt.new_validator(
        expected_issuer='joe', fixed_now=DATETIME_1970)
    verified_jwt = verify.verify_and_decode(signed_compact, validator)
    self.assertEqual(verified_jwt.issuer(), 'joe')
    self.assertEqual(verified_jwt.expiration().year, 2011)
    self.assertCountEqual(verified_jwt.custom_claim_names(),
                          ['http://example.com/is_root'])
    self.assertTrue(verified_jwt.custom_claim('http://example.com/is_root'))

    # fails because it is expired
    with self.assertRaises(tink.TinkError):
      verify.verify_and_decode(
          signed_compact,
          jwt.new_validator(expected_issuer='joe', fixed_now=DATETIME_2020))

    # wrong issuer
    with self.assertRaises(tink.TinkError):
      verify.verify_and_decode(
          signed_compact,
          jwt.new_validator(expected_issuer='jane', fixed_now=DATETIME_1970))

    # invalid format
    with self.assertRaises(tink.TinkError):
      verify.verify_and_decode(signed_compact + '.123', validator)

    # invalid character
    with self.assertRaises(tink.TinkError):
      verify.verify_and_decode(signed_compact + '?', validator)

    # modified signature
    with self.assertRaises(tink.TinkError):
      verify.verify_and_decode(signed_compact + 'a', validator)

    # modified header
    # TODO(juerg): Add better tests.
    with self.assertRaises(tink.TinkError):
      verify.verify_and_decode('a' + signed_compact, validator)

    # TODO(juerg): Add tests with kid headers

  def test_create_sign_verify_with_type_header(self):
    handle = tink.new_keyset_handle(jwt.jwt_es256_template())
    sign = handle.primitive(jwt.JwtPublicKeySign)
    verify = handle.public_keyset_handle().primitive(jwt.JwtPublicKeyVerify)
    raw_jwt = jwt.new_raw_jwt(
        type_header='typeHeader', issuer='joe', without_expiration=True)
    signed_compact = sign.sign_and_encode(raw_jwt)

    validator = jwt.new_validator(
        expected_type_header='typeHeader',
        expected_issuer='joe',
        allow_missing_expiration=True)
    verified_jwt = verify.verify_and_decode(signed_compact, validator)
    self.assertEqual(verified_jwt.type_header(), 'typeHeader')

  def test_verify_with_other_key_fails(self):
    handle = tink.new_keyset_handle(jwt.jwt_es256_template())
    sign = handle.primitive(jwt.JwtPublicKeySign)
    raw_jwt = jwt.new_raw_jwt(issuer='issuer', without_expiration=True)
    compact = sign.sign_and_encode(raw_jwt)

    other_handle = tink.new_keyset_handle(jwt.jwt_es256_template())
    other_verify = other_handle.public_keyset_handle().primitive(
        jwt.JwtPublicKeyVerify)
    with self.assertRaises(tink.TinkError):
      other_verify.verify_and_decode(
          compact,
          jwt.new_validator(
              expected_issuer='issuer', allow_missing_expiration=True))

  def test_bad_tokens_with_valid_signatures_fail(self):
    handle = tink.new_keyset_handle(jwt.jwt_es256_template())
    sign = handle.primitive(jwt.JwtPublicKeySign)
    # get the raw sign primitive, so that we can create correct signatures
    wrapped = cast(_jwt_signature_wrappers._WrappedJwtPublicKeySign, sign)
    raw_sign = cast(_jwt_signature_key_manager._JwtPublicKeySign,
                    wrapped._primitive_set.primary().primitive)._public_key_sign

    verify = handle.public_keyset_handle().primitive(jwt.JwtPublicKeyVerify)
    validator = jwt.new_validator(
        expected_issuer='issuer', allow_missing_expiration=True)

    valid_compact = gen_compact('{"alg":"ES256"}', '{"iss":"issuer"}', raw_sign)
    verified_jwt = verify.verify_and_decode(valid_compact, validator)
    self.assertEqual(verified_jwt.issuer(), 'issuer')

    alg_invalid = gen_compact('{"alg":"ES384"}', '{"iss":"issuer"}', raw_sign)
    with self.assertRaises(tink.TinkError):
      verify.verify_and_decode(alg_invalid, validator)

    header_invalid = gen_compact('{"alg":"ES256"', '{"iss":"issuer"}', raw_sign)
    with self.assertRaises(tink.TinkError):
      verify.verify_and_decode(header_invalid, validator)

    payload_invalid = gen_compact('{"alg":"ES256"}', '{"iss":"issuer"',
                                  raw_sign)
    with self.assertRaises(tink.TinkError):
      verify.verify_and_decode(payload_invalid, validator)

  def test_create_ecdsa_handle_with_invalid_algorithm_fails(self):
    key_format = jwt_ecdsa_pb2.JwtEcdsaKeyFormat(
        algorithm=jwt_ecdsa_pb2.ES_UNKNOWN)
    template = tink_pb2.KeyTemplate(
        type_url='type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey',
        value=key_format.SerializeToString(),
        output_prefix_type=tink_pb2.RAW)
    with self.assertRaises(tink.TinkError):
      tink.new_keyset_handle(template)

  def test_create_sign_primitive_with_invalid_algorithm_fails(self):
    handle = tink.new_keyset_handle(jwt.jwt_es256_template())
    key = jwt_ecdsa_pb2.JwtEcdsaPrivateKey.FromString(
        handle._keyset.key[0].key_data.value)
    key.public_key.algorithm = jwt_ecdsa_pb2.ES_UNKNOWN
    handle._keyset.key[0].key_data.value = key.SerializeToString()
    with self.assertRaises(tink.TinkError):
      handle.primitive(jwt.JwtPublicKeySign)

  def test_create_verify_primitive_with_invalid_algorithm_fails(self):
    private_handle = tink.new_keyset_handle(jwt.jwt_es256_template())
    handle = private_handle.public_keyset_handle()
    key = jwt_ecdsa_pb2.JwtEcdsaPublicKey.FromString(
        handle._keyset.key[0].key_data.value)
    key.algorithm = jwt_ecdsa_pb2.ES_UNKNOWN
    handle._keyset.key[0].key_data.value = key.SerializeToString()
    with self.assertRaises(tink.TinkError):
      handle.primitive(jwt.JwtPublicKeyVerify)


if __name__ == '__main__':
  absltest.main()
