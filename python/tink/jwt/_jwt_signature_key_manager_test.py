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

from typing import cast

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


def gen_compact(json_header: str, json_payload: str, raw_sign) -> str:
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
    with self.assertRaises(tink.TinkError):
      verify.verify_and_decode('a' + signed_compact, validator)

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

  def test_weird_tokens_with_valid_signatures(self):
    handle = tink.new_keyset_handle(jwt.raw_jwt_es256_template())
    sign = handle.primitive(jwt.JwtPublicKeySign)
    # Get the internal PublicKeySign primitive to create valid signatures.
    wrapped = cast(_jwt_signature_wrappers._WrappedJwtPublicKeySign, sign)
    raw_sign = cast(_jwt_signature_key_manager._JwtPublicKeySign,
                    wrapped._primitive_set.primary().primitive)._public_key_sign

    verify = handle.public_keyset_handle().primitive(jwt.JwtPublicKeyVerify)
    validator = jwt.new_validator(
        expected_issuer='issuer', allow_missing_expiration=True)

    # Normal token.
    valid = gen_compact('{"alg":"ES256"}', '{"iss":"issuer"}', raw_sign)
    verified_jwt = verify.verify_and_decode(valid, validator)
    self.assertEqual(verified_jwt.issuer(), 'issuer')

    # Token with unknown header is valid.
    unknown_header = gen_compact('{"alg":"ES256","unknown_header":"abc"} \n ',
                                 '{"iss":"issuer" }', raw_sign)
    verified_jwt = verify.verify_and_decode(unknown_header, validator)
    self.assertEqual(verified_jwt.issuer(), 'issuer')

    # Token with unknown kid is valid, since primitives with output prefix type
    # RAW ignore kid headers.
    unknown_header = gen_compact('{"alg":"ES256","kid":"unknown"} \n ',
                                 '{"iss":"issuer" }', raw_sign)
    verified_jwt = verify.verify_and_decode(unknown_header, validator)
    self.assertEqual(verified_jwt.issuer(), 'issuer')

    # Token with invalid alg header
    alg_invalid = gen_compact('{"alg":"ES384"}', '{"iss":"issuer"}', raw_sign)
    with self.assertRaises(tink.TinkError):
      verify.verify_and_decode(alg_invalid, validator)

    # Token with empty header
    empty_header = gen_compact('{}', '{"iss":"issuer"}', raw_sign)
    with self.assertRaises(tink.TinkError):
      verify.verify_and_decode(empty_header, validator)

    # Token header is not valid JSON
    header_invalid = gen_compact('{"alg":"ES256"', '{"iss":"issuer"}', raw_sign)
    with self.assertRaises(tink.TinkError):
      verify.verify_and_decode(header_invalid, validator)

    # Token payload is not valid JSON
    payload_invalid = gen_compact('{"alg":"ES256"}', '{"iss":"issuer"',
                                  raw_sign)
    with self.assertRaises(tink.TinkError):
      verify.verify_and_decode(payload_invalid, validator)

    # Token with whitespace in header JSON string is valid.
    whitespace_in_header = gen_compact(' {"alg":   \n  "ES256"} \n ',
                                       '{"iss":"issuer" }', raw_sign)
    verified_jwt = verify.verify_and_decode(whitespace_in_header, validator)
    self.assertEqual(verified_jwt.issuer(), 'issuer')

    # Token with whitespace in payload JSON string is valid.
    whitespace_in_payload = gen_compact('{"alg":"ES256"}',
                                        ' {"iss": \n"issuer" } \n', raw_sign)
    verified_jwt = verify.verify_and_decode(whitespace_in_payload, validator)
    self.assertEqual(verified_jwt.issuer(), 'issuer')

    # Token with whitespace in base64-encoded header is invalid.
    with_whitespace = (
        _jwt_format.encode_header('{"alg":"ES256"}') + b' .' +
        _jwt_format.encode_payload('{"iss":"issuer"}'))
    token_with_whitespace = _jwt_format.create_signed_compact(
        with_whitespace, raw_sign.sign(with_whitespace))
    with self.assertRaises(tink.TinkError):
      verify.verify_and_decode(token_with_whitespace, validator)

    # Token with invalid character is invalid.
    with_invalid_char = (
        _jwt_format.encode_header('{"alg":"ES256"}') + b'.?' +
        _jwt_format.encode_payload('{"iss":"issuer"}'))
    token_with_invalid_char = _jwt_format.create_signed_compact(
        with_invalid_char, raw_sign.sign(with_invalid_char))
    with self.assertRaises(tink.TinkError):
      verify.verify_and_decode(token_with_invalid_char, validator)

    # Token with additional '.' is invalid.
    with_dot = (
        _jwt_format.encode_header('{"alg":"ES256"}') + b'.' +
        _jwt_format.encode_payload('{"iss":"issuer"}') + b'.')
    token_with_dot = _jwt_format.create_signed_compact(
        with_dot, raw_sign.sign(with_dot))
    with self.assertRaises(tink.TinkError):
      verify.verify_and_decode(token_with_dot, validator)

    # num_recursions has been chosen such that parsing of this token fails
    # in all languages. We want to make sure that the algorithm does not
    # hang or crash in this case, but only returns a parsing error.
    num_recursions = 10000
    rec_payload = ('{"a":' * num_recursions) + '""' + ('}' * num_recursions)
    rec_token = gen_compact('{"alg":"ES256"}', rec_payload, raw_sign)
    with self.assertRaises(tink.TinkError):
      verify.verify_and_decode(
          rec_token, validator=jwt.new_validator(allow_missing_expiration=True))

    # test wrong types
    with self.assertRaises(tink.TinkError):
      verify.verify_and_decode(cast(str, None), validator)
    with self.assertRaises(tink.TinkError):
      verify.verify_and_decode(cast(str, 123), validator)
    with self.assertRaises(tink.TinkError):
      valid_bytes = valid.encode('utf8')
      verify.verify_and_decode(cast(str, valid_bytes), validator)

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
