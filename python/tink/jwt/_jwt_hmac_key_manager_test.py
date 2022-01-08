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
"""Tests for tink.python.tink.jwt._jwt_hmac_key_manager."""

import base64
import datetime

from typing import cast, Any

from absl.testing import absltest
from absl.testing import parameterized

from tink.proto import jwt_hmac_pb2
from tink.proto import tink_pb2
import tink
from tink import jwt
from tink.cc.pybind import tink_bindings
from tink.jwt import _jwt_format
from tink.jwt import _jwt_hmac_key_manager
from tink.jwt import _jwt_mac


DATETIME_1970 = datetime.datetime.fromtimestamp(12345, datetime.timezone.utc)
DATETIME_2020 = datetime.datetime.fromtimestamp(1582230020,
                                                datetime.timezone.utc)


def setUpModule():
  _jwt_hmac_key_manager.register()


def _fixed_key_data() -> tink_pb2.KeyData:
  # test example in https://tools.ietf.org/html/rfc7515#appendix-A.1.1
  key_encoded = (b'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_'
                 b'T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow')
  padded_key_encoded = key_encoded + b'=' * (-len(key_encoded) % 4)
  key_value = base64.urlsafe_b64decode(padded_key_encoded)
  jwt_hmac_key = jwt_hmac_pb2.JwtHmacKey(
      version=0, algorithm=jwt_hmac_pb2.HS256, key_value=key_value)
  return tink_pb2.KeyData(
      type_url='type.googleapis.com/google.crypto.tink.JwtHmacKey',
      key_material_type=tink_pb2.KeyData.SYMMETRIC,
      value=jwt_hmac_key.SerializeToString())


def _cc_mac() -> Any:
  key_data = _fixed_key_data()
  cc_key_manager = tink_bindings.MacKeyManager.from_cc_registry(
      'type.googleapis.com/google.crypto.tink.JwtHmacKey')
  return cc_key_manager.primitive(key_data.SerializeToString())


def create_fixed_jwt_hmac() -> _jwt_mac.JwtMacInternal:
  key_data = _fixed_key_data()
  key_manager = _jwt_hmac_key_manager.MacCcToPyJwtMacKeyManager()
  return key_manager.primitive(key_data)


def gen_token(json_header: str, json_payload: str) -> str:
  cc_mac = _cc_mac()
  unsigned_token = (
      _jwt_format.encode_header(json_header) + b'.' +
      _jwt_format.encode_payload(json_payload))
  return _jwt_format.create_signed_compact(unsigned_token,
                                           cc_mac.compute_mac(unsigned_token))


class JwtHmacKeyManagerTest(parameterized.TestCase):

  def test_basic(self):
    key_manager = _jwt_hmac_key_manager.MacCcToPyJwtMacKeyManager()
    self.assertEqual(key_manager.primitive_class(), _jwt_mac.JwtMacInternal)
    self.assertEqual(key_manager.key_type(),
                     'type.googleapis.com/google.crypto.tink.JwtHmacKey')

  @parameterized.named_parameters([
      ('JWT_HS256', jwt.raw_jwt_hs256_template()),
      ('JWT_HS384', jwt.raw_jwt_hs384_template()),
      ('JWT_HS512', jwt.raw_jwt_hs512_template()),
  ])
  def test_new_keydata_primitive_success(self, template):
    key_manager = _jwt_hmac_key_manager.MacCcToPyJwtMacKeyManager()
    key_data = key_manager.new_key_data(template)
    jwt_hmac = key_manager.primitive(key_data)

    raw_jwt = jwt.new_raw_jwt(
        type_header='typeHeader', issuer='issuer', without_expiration=True)
    validator = jwt.new_validator(
        expected_type_header='typeHeader',
        expected_issuer='issuer',
        allow_missing_expiration=True,
        fixed_now=DATETIME_1970)

    token_with_kid = jwt_hmac.compute_mac_and_encode_with_kid(
        raw_jwt, kid='kid-123')
    token_without_kid = jwt_hmac.compute_mac_and_encode_with_kid(
        raw_jwt, kid=None)

    # Verification of a token with a kid only fails if the wrong kid is passed.
    verified_jwt = jwt_hmac.verify_mac_and_decode_with_kid(
        token_with_kid, validator, kid='kid-123')
    self.assertEqual(verified_jwt.type_header(), 'typeHeader')
    self.assertEqual(verified_jwt.issuer(), 'issuer')
    jwt_hmac.verify_mac_and_decode_with_kid(token_with_kid, validator, kid=None)
    with self.assertRaises(tink.TinkError):
      jwt_hmac.verify_mac_and_decode_with_kid(
          token_with_kid, validator, kid='other-kid')

    # A token without kid is only valid if no kid is passed.
    jwt_hmac.verify_mac_and_decode_with_kid(
        token_without_kid, validator, kid=None)
    with self.assertRaises(tink.TinkError):
      jwt_hmac.verify_mac_and_decode_with_kid(
          token_without_kid, validator, kid='kid-123')

  def test_fixed_signed_compact(self):
    signed_compact = (
        'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleH'
        'AiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.'
        'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')
    jwt_hmac = create_fixed_jwt_hmac()
    verified_jwt = jwt_hmac.verify_mac_and_decode_with_kid(
        signed_compact,
        jwt.new_validator(
            expected_type_header='JWT',
            expected_issuer='joe',
            fixed_now=DATETIME_1970),
        kid=None)
    self.assertEqual(verified_jwt.issuer(), 'joe')
    self.assertEqual(verified_jwt.expiration().year, 2011)
    self.assertCountEqual(verified_jwt.custom_claim_names(),
                          ['http://example.com/is_root'])
    self.assertTrue(verified_jwt.custom_claim('http://example.com/is_root'))
    self.assertTrue(verified_jwt.type_header(), 'JWT')

    # fails because it is expired
    with self.assertRaises(tink.TinkError):
      jwt_hmac.verify_mac_and_decode_with_kid(
          signed_compact, jwt.new_validator(fixed_now=DATETIME_2020), kid=None)

    # fails with wrong issuer
    with self.assertRaises(tink.TinkError):
      jwt_hmac.verify_mac_and_decode_with_kid(
          signed_compact,
          jwt.new_validator(expected_issuer='jane', fixed_now=DATETIME_1970),
          kid=None)

  def test_weird_tokens_with_valid_macs(self):
    jwt_hmac = create_fixed_jwt_hmac()
    validator = jwt.new_validator(
        expected_issuer='joe', allow_missing_expiration=True)
    cc_mac = _cc_mac()

    # Normal token.
    valid_token = gen_token('{"alg":"HS256"}', '{"iss":"joe"}')
    verified = jwt_hmac.verify_mac_and_decode_with_kid(
        valid_token, validator, kid=None)
    self.assertEqual(verified.issuer(), 'joe')

    # Token with unknown header is valid.
    token_with_unknown_header = gen_token(
        '{"unknown_header":"123","alg":"HS256"}', '{"iss":"joe"}')
    verified2 = jwt_hmac.verify_mac_and_decode_with_kid(
        token_with_unknown_header, validator, kid=None)
    self.assertEqual(verified2.issuer(), 'joe')

    # Token with unknown kid is valid, since primitives with output prefix type
    # RAW ignore kid headers.
    token_with_unknown_kid = gen_token('{"kid":"unknown","alg":"HS256"}',
                                       '{"iss":"joe"}')
    verified2 = jwt_hmac.verify_mac_and_decode_with_kid(
        token_with_unknown_kid, validator, kid=None)
    self.assertEqual(verified2.issuer(), 'joe')

    # Token with invalid alg header
    alg_invalid = gen_token('{"alg":"HS384"}', '{"iss":"joe"}')
    with self.assertRaises(tink.TinkError):
      jwt_hmac.verify_mac_and_decode_with_kid(alg_invalid, validator, kid=None)

    # Token with empty header
    empty_header = gen_token('{}', '{"iss":"joe"}')
    with self.assertRaises(tink.TinkError):
      jwt_hmac.verify_mac_and_decode_with_kid(empty_header, validator, kid=None)

    # Token header is not valid JSON
    header_invalid = gen_token('{"alg":"HS256"', '{"iss":"joe"}')
    with self.assertRaises(tink.TinkError):
      jwt_hmac.verify_mac_and_decode_with_kid(
          header_invalid, validator, kid=None)

    # Token payload is not valid JSON
    payload_invalid = gen_token('{"alg":"HS256"}', '{"iss":"joe"')
    with self.assertRaises(tink.TinkError):
      jwt_hmac.verify_mac_and_decode_with_kid(
          payload_invalid, validator, kid=None)

    # Token with whitespace in header JSON string is valid.
    whitespace_in_header = gen_token(' {"alg":   \n  "HS256"} \n ',
                                     '{"iss":"joe" }')
    verified_jwt = jwt_hmac.verify_mac_and_decode_with_kid(
        whitespace_in_header, validator, kid=None)
    self.assertEqual(verified_jwt.issuer(), 'joe')

    # Token with whitespace in payload JSON string is valid.
    whitespace_in_payload = gen_token('{"alg":"HS256"}',
                                      ' {"iss": \n"joe" } \n')
    verified_jwt = jwt_hmac.verify_mac_and_decode_with_kid(
        whitespace_in_payload, validator, kid=None)
    self.assertEqual(verified_jwt.issuer(), 'joe')

    # Token with whitespace in base64-encoded header is invalid.
    with_whitespace_in_encoding = (
        _jwt_format.encode_header('{"alg":"HS256"}') + b' .' +
        _jwt_format.encode_payload('{"iss":"joe"}'))
    token_with_whitespace_in_encoding = _jwt_format.create_signed_compact(
        with_whitespace_in_encoding,
        cc_mac.compute_mac(with_whitespace_in_encoding))
    with self.assertRaises(tink.TinkError):
      jwt_hmac.verify_mac_and_decode_with_kid(
          token_with_whitespace_in_encoding, validator, kid=None)

    # Token with invalid character is invalid.
    with_invalid_char = (
        _jwt_format.encode_header('{"alg":"HS256"}') + b'.?' +
        _jwt_format.encode_payload('{"iss":"joe"}'))
    token_with_invalid_char = _jwt_format.create_signed_compact(
        with_invalid_char, cc_mac.compute_mac(with_invalid_char))
    with self.assertRaises(tink.TinkError):
      jwt_hmac.verify_mac_and_decode_with_kid(
          token_with_invalid_char, validator, kid=None)

    # Token with additional '.' is invalid.
    with_dot = (
        _jwt_format.encode_header('{"alg":"HS256"}') + b'.' +
        _jwt_format.encode_payload('{"iss":"joe"}') + b'.')
    token_with_dot = _jwt_format.create_signed_compact(
        with_dot, cc_mac.compute_mac(with_dot))
    with self.assertRaises(tink.TinkError):
      jwt_hmac.verify_mac_and_decode_with_kid(
          token_with_dot, validator, kid=None)

    # num_recursions has been chosen such that parsing of this token fails
    # in all languages. We want to make sure that the algorithm does not
    # hang or crash in this case, but only returns a parsing error.
    num_recursions = 10000
    rec_payload = ('{"a":' * num_recursions) + '""' + ('}' * num_recursions)
    rec_token = gen_token('{"alg":"HS256"}', rec_payload)
    with self.assertRaises(tink.TinkError):
      jwt_hmac.verify_mac_and_decode_with_kid(
          rec_token,
          validator=jwt.new_validator(allow_missing_expiration=True),
          kid=None)

    # test wrong types
    with self.assertRaises(tink.TinkError):
      jwt_hmac.verify_mac_and_decode_with_kid(
          cast(str, None), validator, kid=None)
    with self.assertRaises(tink.TinkError):
      jwt_hmac.verify_mac_and_decode_with_kid(
          cast(str, 123), validator, kid=None)
    with self.assertRaises(tink.TinkError):
      valid_token_bytes = valid_token.encode('utf8')
      jwt_hmac.verify_mac_and_decode_with_kid(
          cast(str, valid_token_bytes), validator, kid=None)

  @parameterized.named_parameters([
      ('modified_signature',
       ('eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleH'
        'AiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.'
        'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXi')),
      ('modified_payload',
       ('eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOj'
        'EzMDA4MTkzODEsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.'
        'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')),
      ('modified_header',
       ('eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleH'
        'AiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.'
        'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')),
      ('extra .', 'eyJhbGciOiJIUzI1NiJ9.e30.abc.'),
      ('invalid_header_encoding', 'eyJhbGciOiJIUzI1NiJ9?.e30.abc'),
      ('invalid_payload_encoding', 'eyJhbGciOiJIUzI1NiJ9.e30?.abc'),
      ('invalid_mac_encoding', 'eyJhbGciOiJIUzI1NiJ9.e30.abc?'),
      ('no_mac', 'eyJhbGciOiJIUzI1NiJ9.e30'),
  ])
  def test_invalid_signed_compact(self, invalid_signed_compact):
    jwt_hmac = create_fixed_jwt_hmac()
    validator = jwt.new_validator(
        expected_issuer='joe',
        allow_missing_expiration=True,
        fixed_now=DATETIME_1970)

    with self.assertRaises(tink.TinkError):
      jwt_hmac.verify_mac_and_decode_with_kid(
          invalid_signed_compact, validator, kid=None)


if __name__ == '__main__':
  absltest.main()
