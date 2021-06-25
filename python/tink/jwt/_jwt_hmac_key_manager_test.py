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

from typing import Text

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


def create_fixed_jwt_hmac() -> jwt.JwtMac:
  key_data = _fixed_key_data()
  key_manager = _jwt_hmac_key_manager.MacCcToPyJwtMacKeyManager()
  return key_manager.primitive(key_data)


def create_signed_token(json_header: Text, json_payload: Text) -> Text:
  key_data = _fixed_key_data()
  cc_key_manager = tink_bindings.MacKeyManager.from_cc_registry(
      'type.googleapis.com/google.crypto.tink.JwtHmacKey')
  cc_mac = cc_key_manager.primitive(key_data.SerializeToString())
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
      ('JWT_HS256', jwt.jwt_hs256_template()),
      ('JWT_HS384', jwt.jwt_hs384_template()),
      ('JWT_HS512', jwt.jwt_hs512_template()),
  ])
  def test_new_keydata_primitive_success(self, template):
    key_manager = _jwt_hmac_key_manager.MacCcToPyJwtMacKeyManager()
    key_data = key_manager.new_key_data(template)
    jwt_hmac = key_manager.primitive(key_data)

    raw_jwt = jwt.new_raw_jwt(
        type_header='typeHeader', issuer='issuer', without_expiration=True)
    signed_compact = jwt_hmac.compute_mac_and_encode_with_kid(raw_jwt, None)

    verified_jwt = jwt_hmac.verify_mac_and_decode(
        signed_compact,
        jwt.new_validator(
            expected_type_header='typeHeader',
            expected_issuer='issuer',
            allow_missing_expiration=True,
            fixed_now=DATETIME_1970))
    self.assertEqual(verified_jwt.type_header(), 'typeHeader')
    self.assertEqual(verified_jwt.issuer(), 'issuer')

  def test_fixed_signed_compact(self):
    signed_compact = (
        'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleH'
        'AiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.'
        'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')
    jwt_hmac = create_fixed_jwt_hmac()
    verified_jwt = jwt_hmac.verify_mac_and_decode(
        signed_compact,
        jwt.new_validator(
            expected_type_header='JWT',
            expected_issuer='joe',
            fixed_now=DATETIME_1970))
    self.assertEqual(verified_jwt.issuer(), 'joe')
    self.assertEqual(verified_jwt.expiration().year, 2011)
    self.assertCountEqual(verified_jwt.custom_claim_names(),
                          ['http://example.com/is_root'])
    self.assertTrue(verified_jwt.custom_claim('http://example.com/is_root'))
    self.assertTrue(verified_jwt.type_header(), 'JWT')

    # fails because it is expired
    with self.assertRaises(tink.TinkError):
      jwt_hmac.verify_mac_and_decode(signed_compact,
                                     jwt.new_validator(fixed_now=DATETIME_2020))

    # fails with wrong issuer
    with self.assertRaises(tink.TinkError):
      jwt_hmac.verify_mac_and_decode(
          signed_compact,
          jwt.new_validator(expected_issuer='jane', fixed_now=DATETIME_1970))

  def test_valid_signed_compact(self):
    jwt_hmac = create_fixed_jwt_hmac()

    valid_token = create_signed_token('{"alg":"HS256"}', '{"iss":"joe"}')
    verified = jwt_hmac.verify_mac_and_decode(
        valid_token,
        jwt.new_validator(
            expected_issuer='joe',
            allow_missing_expiration=True,
            fixed_now=DATETIME_1970))
    self.assertEqual(verified.issuer(), 'joe')

    token_with_unknown_typ = create_signed_token(
        '{"alg":"HS256","typ":"unknown"}', '{"iss":"joe"}')
    verified2 = jwt_hmac.verify_mac_and_decode(
        token_with_unknown_typ,
        jwt.new_validator(
            expected_type_header='unknown',
            expected_issuer='joe',
            allow_missing_expiration=True,
            fixed_now=DATETIME_1970))
    self.assertEqual(verified2.issuer(), 'joe')

    token_with_unknown_kid = create_signed_token(
        '{"kid":"unknown","alg":"HS256"}', '{"iss":"joe"}')
    verified2 = jwt_hmac.verify_mac_and_decode(
        token_with_unknown_kid,
        jwt.new_validator(
            expected_issuer='joe',
            allow_missing_expiration=True,
            fixed_now=DATETIME_1970))
    self.assertEqual(verified2.issuer(), 'joe')

  def test_invalid_signed_compact_with_valid_signature(self):
    jwt_hmac = create_fixed_jwt_hmac()
    validator = jwt.new_validator(
        expected_issuer='joe',
        allow_missing_expiration=True,
        fixed_now=DATETIME_1970)

    # token with valid signature but invalid alg header
    token_with_invalid_header = create_signed_token('{"alg":"RS256"}',
                                                    '{"iss":"joe"}')
    with self.assertRaises(tink.TinkError):
      jwt_hmac.verify_mac_and_decode(token_with_invalid_header, validator)

    # token with valid signature but invalid json in payload
    token_with_invalid_payload = create_signed_token('{"alg":"HS256"}',
                                                     '{"iss":"joe"')
    with self.assertRaises(tink.TinkError):
      jwt_hmac.verify_mac_and_decode(token_with_invalid_payload, validator)

  @parameterized.named_parameters([
      ('modified_signature',
       'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleH'
       'AiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.'
       'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXi'),
      ('modified_payload',
       'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLCJleHAiOj'
       'EzMDA4MTkzODEsImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.'
       'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'),
      ('modified_header',
       'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleH'
       'AiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.'
       'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'),
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
      jwt_hmac.verify_mac_and_decode(invalid_signed_compact, validator)


if __name__ == '__main__':
  absltest.main()
