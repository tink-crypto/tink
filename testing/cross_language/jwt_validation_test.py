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
"""Cross-language tests for JWT validation.

These tests test the non-cryptographic JWT validation. The tokens are MACed
with the same key and the MAC is always valid. We test how the validation
handles weird headers or payloads.
"""

import base64
import datetime

from absl.testing import absltest
from absl.testing import parameterized
import tink
from tink import cleartext_keyset_handle
from tink import jwt
from tink import mac

from tink.proto import common_pb2
from tink.proto import hmac_pb2
from tink.proto import jwt_hmac_pb2
from tink.proto import tink_pb2
from util import testing_servers

SUPPORTED_LANGUAGES = testing_servers.SUPPORTED_LANGUAGES_BY_PRIMITIVE['jwt']

# Example from https://tools.ietf.org/html/rfc7519#section-3.1
EXAMPLE_TOKEN = ('eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.'
                 'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQo'
                 'gImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.'
                 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')
KEY_VALUE = (b'AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-'
             b'1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow==')
KEYSET = None
MAC = None
EMPTY_VALIDATOR = jwt.new_validator(allow_missing_expiration=True)


def _base64_encode(data: bytes) -> bytes:
  """Does a URL-safe base64 encoding without padding."""
  return base64.urlsafe_b64encode(data).rstrip(b'=')


def _keyset() -> bytes:
  jwt_hmac_key = jwt_hmac_pb2.JwtHmacKey(
      version=0,
      algorithm=jwt_hmac_pb2.HS256,
      key_value=base64.urlsafe_b64decode(KEY_VALUE))
  keyset = tink_pb2.Keyset()
  key = keyset.key.add()
  key.key_data.type_url = ('type.googleapis.com/google.crypto.tink.JwtHmacKey')
  key.key_data.value = jwt_hmac_key.SerializeToString()
  key.key_data.key_material_type = tink_pb2.KeyData.SYMMETRIC
  key.status = tink_pb2.ENABLED
  key.key_id = 123
  key.output_prefix_type = tink_pb2.RAW
  keyset.primary_key_id = 123
  return keyset.SerializeToString()


def _mac() -> mac.Mac:
  hmac_key = hmac_pb2.HmacKey(
      version=0, key_value=base64.urlsafe_b64decode(KEY_VALUE))
  hmac_key.params.hash = common_pb2.SHA256
  hmac_key.params.tag_size = 32
  keyset = tink_pb2.Keyset()
  key = keyset.key.add()
  key.key_data.type_url = ('type.googleapis.com/google.crypto.tink.HmacKey')
  key.key_data.value = hmac_key.SerializeToString()
  key.key_data.key_material_type = tink_pb2.KeyData.SYMMETRIC
  key.status = tink_pb2.ENABLED
  key.key_id = 123
  key.output_prefix_type = tink_pb2.RAW
  keyset.primary_key_id = 123
  keyset_handle = cleartext_keyset_handle.from_keyset(keyset)
  return keyset_handle.primitive(mac.Mac)


def setUpModule():
  global KEYSET, MAC
  jwt.register_jwt_mac()
  mac.register()
  testing_servers.start('jwt')
  KEYSET = _keyset()
  MAC = _mac()


def tearDownModule():
  testing_servers.stop()


def generate_token_from_bytes(header: bytes, payload: bytes) -> str:
  """Generates tokens from bytes with valid MACs."""
  unsigned_compact = (_base64_encode(header) + b'.' + _base64_encode(payload))
  mac_value = MAC.compute_mac(unsigned_compact)
  return (unsigned_compact + b'.' + _base64_encode(mac_value)).decode('utf8')


def generate_token(header: str, payload: str) -> str:
  """Generates tokens with valid MACs."""
  return generate_token_from_bytes(
      header.encode('utf8'), payload.encode('utf8'))


class JwtTest(parameterized.TestCase):

  def test_genenerate_token_generates_example(self):
    token = generate_token(
        '{"typ":"JWT",\r\n "alg":"HS256"}',
        '{"iss":"joe",\r\n "exp":1300819380,\r\n '
        '"http://example.com/is_root":true}')
    self.assertEqual(token, EXAMPLE_TOKEN)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_valid(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"jti":"123"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    verified_jwt = jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)
    self.assertEqual(verified_jwt.jwt_id(), '123')

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_unknown_header_valid(self, lang):
    token = generate_token('{"alg":"HS256", "unknown":{"a":"b"}}',
                           '{"jti":"123"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    verified_jwt = jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)
    self.assertEqual(verified_jwt.jwt_id(), '123')

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_empty_crit_header_invalid(self, lang):
    # See https://tools.ietf.org/html/rfc7515#section-4.1.11
    token = generate_token('{"alg":"HS256", "crit":[]}', '{"jti":"123"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_nonempty_crit_header_invalid(self, lang):
    # See https://tools.ietf.org/html/rfc7515#section-4.1.11
    token = generate_token(
        '{"alg":"HS256","crit":["http://example.invalid/UNDEFINED"],'
        '"http://example.invalid/UNDEFINED":true}', '{"jti":"123"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_typ_header(self, lang):
    token = generate_token(
        '{"typ":"typeHeader", "alg":"HS256"}', '{"jti":"123"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    validator_with_correct_type_header = jwt.new_validator(
        expected_type_header='typeHeader', allow_missing_expiration=True)
    jwt_mac.verify_mac_and_decode(token, validator_with_correct_type_header)

    validator_with_missing_type_header = jwt.new_validator(
        allow_missing_expiration=True)
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, validator_with_missing_type_header)

    validator_that_ignores_type_header = jwt.new_validator(
        ignore_type_header=True, allow_missing_expiration=True)
    jwt_mac.verify_mac_and_decode(token, validator_that_ignores_type_header)

    validator_with_wrong_type_header = jwt.new_validator(
        expected_type_header='typeHeader', allow_missing_expiration=True)
    jwt_mac.verify_mac_and_decode(token, validator_with_wrong_type_header)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_expiration(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"jti":"123", "exp":1234}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    # same time is expired.
    validator_with_same_time = jwt.new_validator(
        fixed_now=datetime.datetime.fromtimestamp(1234, datetime.timezone.utc))
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, validator_with_same_time)

    # a second before is fine
    validator_before = jwt.new_validator(
        fixed_now=datetime.datetime.fromtimestamp(1233,
                                                  datetime.timezone.utc))
    jwt_mac.verify_mac_and_decode(token, validator_before)

    # 3 seconds too late with 3 seconds clock skew is expired.
    validator_too_late_with_clockskew = jwt.new_validator(
        fixed_now=datetime.datetime.fromtimestamp(1237, datetime.timezone.utc),
        clock_skew=datetime.timedelta(seconds=3))
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, validator_too_late_with_clockskew)

    # 2 seconds too late with 3 seconds clock skew is fine.
    validator_still_ok_with_clockskew = jwt.new_validator(
        fixed_now=datetime.datetime.fromtimestamp(1236, datetime.timezone.utc),
        clock_skew=datetime.timedelta(seconds=3))
    jwt_mac.verify_mac_and_decode(token, validator_still_ok_with_clockskew)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_float_expiration(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"jti":"123", "exp":1234.5}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    validate_after = jwt.new_validator(
        fixed_now=datetime.datetime.fromtimestamp(1235.5,
                                                  datetime.timezone.utc))
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, validate_after)

    validate_before = jwt.new_validator(
        fixed_now=datetime.datetime.fromtimestamp(1233.5,
                                                  datetime.timezone.utc))
    jwt_mac.verify_mac_and_decode(token, validate_before)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_exp_expiration_is_fine(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"exp":1e10}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_large_expiration_is_fine(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"exp":253402300799}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_too_large_expiration_is_invalid(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"exp":253402300800}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_way_too_large_expiration_is_invalid(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"exp":1e30}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_infinity_expiration_is_invalid(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"jti":"123", "exp":Infinity}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_not_before(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"jti":"123", "nbf":1234}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    # same time as not-before fine.
    validator_same_time = jwt.new_validator(
        allow_missing_expiration=True,
        fixed_now=datetime.datetime.fromtimestamp(1234, datetime.timezone.utc))
    jwt_mac.verify_mac_and_decode(token, validator_same_time)

    # one second before is not yet valid
    validator_before = jwt.new_validator(
        allow_missing_expiration=True,
        fixed_now=datetime.datetime.fromtimestamp(1233, datetime.timezone.utc))
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, validator_before)

    # 3 seconds too early with 3 seconds clock skew is fine
    validator_ok_with_clockskew = jwt.new_validator(
        allow_missing_expiration=True,
        fixed_now=datetime.datetime.fromtimestamp(1231, datetime.timezone.utc),
        clock_skew=datetime.timedelta(seconds=3))
    jwt_mac.verify_mac_and_decode(token, validator_ok_with_clockskew)

    # 3 seconds too early with 2 seconds clock skew is not yet valid.
    validator_too_early_with_clockskew = jwt.new_validator(
        allow_missing_expiration=True,
        fixed_now=datetime.datetime.fromtimestamp(1231, datetime.timezone.utc),
        clock_skew=datetime.timedelta(seconds=2))
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, validator_too_early_with_clockskew)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_float_not_before(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"jti":"123", "nbf":1234.5}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    validator_before = jwt.new_validator(
        allow_missing_expiration=True,
        fixed_now=datetime.datetime.fromtimestamp(1233.5,
                                                  datetime.timezone.utc))
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, validator_before)

    validator_after = jwt.new_validator(
        allow_missing_expiration=True,
        fixed_now=datetime.datetime.fromtimestamp(1235.5,
                                                  datetime.timezone.utc))
    jwt_mac.verify_mac_and_decode(token, validator_after)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_issued_at(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"jti":"123", "iat":1234}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    # same time as issued-at fine.
    validator_same_time = jwt.new_validator(
        expect_issued_in_the_past=True,
        allow_missing_expiration=True,
        fixed_now=datetime.datetime.fromtimestamp(1234, datetime.timezone.utc))
    jwt_mac.verify_mac_and_decode(token, validator_same_time)

    # one second before is not yet valid
    validator_before = jwt.new_validator(
        expect_issued_in_the_past=True,
        allow_missing_expiration=True,
        fixed_now=datetime.datetime.fromtimestamp(1233, datetime.timezone.utc))
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, validator_before)

    # ten second before but without expect_issued_in_the_past is fine
    validator_without_iat_validation = jwt.new_validator(
        allow_missing_expiration=True,
        fixed_now=datetime.datetime.fromtimestamp(1224, datetime.timezone.utc))
    jwt_mac.verify_mac_and_decode(token, validator_without_iat_validation)

    # 3 seconds too early with 3 seconds clock skew is fine
    validator_ok_with_clockskew = jwt.new_validator(
        expect_issued_in_the_past=True,
        allow_missing_expiration=True,
        fixed_now=datetime.datetime.fromtimestamp(1231, datetime.timezone.utc),
        clock_skew=datetime.timedelta(seconds=3))
    jwt_mac.verify_mac_and_decode(token, validator_ok_with_clockskew)

    # 3 seconds too early with 2 seconds clock skew is not yet valid.
    validator_too_early_with_clockskew = jwt.new_validator(
        expect_issued_in_the_past=True,
        allow_missing_expiration=True,
        fixed_now=datetime.datetime.fromtimestamp(1231, datetime.timezone.utc),
        clock_skew=datetime.timedelta(seconds=2))
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, validator_too_early_with_clockskew)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_issuer(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"iss":"joe"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    validator_with_correct_issuer = jwt.new_validator(
        expected_issuer='joe', allow_missing_expiration=True)
    jwt_mac.verify_mac_and_decode(token, validator_with_correct_issuer)

    validator_without_issuer = jwt.new_validator(allow_missing_expiration=True)
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, validator_without_issuer)

    validator_that_ignores_issuer = jwt.new_validator(
        ignore_issuer=True, allow_missing_expiration=True)
    jwt_mac.verify_mac_and_decode(token, validator_that_ignores_issuer)

    validator_with_wrong_issuer = jwt.new_validator(
        expected_issuer='Joe', allow_missing_expiration=True)
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, validator_with_wrong_issuer)

    val4 = jwt.new_validator(
        expected_issuer='joe ', allow_missing_expiration=True)
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, val4)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_duplicated_issuer(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"iss":"joe", "iss":"jane"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    if lang != 'java' and lang != 'python':
      validator_with_second_issuer = jwt.new_validator(
          ignore_issuer=True, allow_missing_expiration=True)
      with self.assertRaises(tink.TinkError):
        jwt_mac.verify_mac_and_decode(token, validator_with_second_issuer)
    else:
      # Currently, this is accepted in Java and Python, and always the last
      # entry is used.
      # TODO(b/241828611): This should be rejected.
      validator_with_second_issuer = jwt.new_validator(
          expected_issuer='jane', allow_missing_expiration=True)
      jwt_mac.verify_mac_and_decode(token, validator_with_second_issuer)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_empty_string_issuer(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"iss":""}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    jwt_mac.verify_mac_and_decode(
        token,
        jwt.new_validator(expected_issuer='', allow_missing_expiration=True))

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_issuer_with_wrong_type(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"iss":123}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_invalid_utf8_in_header(self, lang):
    token = generate_token_from_bytes(b'{"alg":"HS256", "a":"\xc2"}',
                                      b'{"iss":"joe"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_invalid_utf8_in_payload(self, lang):
    token = generate_token_from_bytes(b'{"alg":"HS256"}', b'{"jti":"joe\xc2"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_with_utf16_surrogate_in_payload(self, lang):
    # The JSON string contains the G clef character (U+1D11E) in UTF8.
    token = generate_token_from_bytes(b'{"alg":"HS256"}',
                                      b'{"jti":"\xF0\x9D\x84\x9E"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    token = jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)
    self.assertEqual(token.jwt_id(), u'\U0001d11e')

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_with_json_escaped_utf16_surrogate_in_payload(self, lang):
    # The JSON string contains "\uD834\uDD1E", which should decode to
    # the G clef character (U+1D11E).
    token = generate_token('{"alg":"HS256"}', '{"jti":"\\uD834\\uDD1E"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    token = jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)
    self.assertEqual(token.jwt_id(), u'\U0001d11e')

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_with_invalid_json_escaped_utf16_in_payload(self, lang):
    # The JSON string contains "\uD834", which gets decoded into an invalid
    # UTF16 character.
    token = generate_token('{"alg":"HS256"}', '{"jti":"\\uD834"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_with_invalid_json_escaped_utf16_in_claim_name(self, lang):
    token = generate_token('{"alg":"HS256"}',
                           '{"\\uD800\\uD800claim":"value"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_audience(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"aud":["joe", "jane"]}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    validator_with_correct_audience = jwt.new_validator(
        expected_audience='joe', allow_missing_expiration=True)
    jwt_mac.verify_mac_and_decode(token, validator_with_correct_audience)

    validator_with_correct_audience2 = jwt.new_validator(
        expected_audience='jane', allow_missing_expiration=True)
    jwt_mac.verify_mac_and_decode(token, validator_with_correct_audience2)

    validator_without_audience = jwt.new_validator(
        allow_missing_expiration=True)
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, validator_without_audience)

    validator_that_ignores_audience = jwt.new_validator(
        ignore_audiences=True, allow_missing_expiration=True)
    jwt_mac.verify_mac_and_decode(token, validator_that_ignores_audience)

    validator_with_wrong_audience = jwt.new_validator(
        expected_audience='Joe', allow_missing_expiration=True)
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, validator_with_wrong_audience)

    val5 = jwt.new_validator(
        expected_audience='jane ', allow_missing_expiration=True)
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, val5)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_audience_string(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"aud":"joe"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    val1 = jwt.new_validator(
        expected_audience='joe', allow_missing_expiration=True)
    jwt_mac.verify_mac_and_decode(token, val1)

    val3 = EMPTY_VALIDATOR
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, val3)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_audiences_with_wrong_type(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"aud":["joe", 123]}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_token_with_empty_audiences(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"aud":[]}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_token_with_utf_16_encoded_payload_fails(self, lang):
    token = generate_token_from_bytes('{"alg":"HS256"}'.encode('utf-8'),
                                      '{"iss":"joe"}'.encode('utf-16'))
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_token_with_utf_32_encoded_payload_fails(self, lang):
    token = generate_token_from_bytes('{"alg":"HS256"}'.encode('utf-8'),
                                      '{"iss":"joe"}'.encode('utf-32'))
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_token_with_many_recursions(self, lang):
    num_recursions = 10
    payload = ('{"a":' * num_recursions) + '""' + ('}' * num_recursions)
    token = generate_token('{"alg":"HS256"}', payload)
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_token_with_too_many_recursions_fails(self, lang):
    # TODO(b/220810178): enable test for golang once depth limit is enabled.
    if lang == 'go': return
    # num_recursions has been chosen such that parsing of this token fails
    # in all languages. We want to make sure that the algorithm does not
    # hang or crash in this case, but only returns a parsing error.
    num_recursions = 10000
    payload = ('{"a":' * num_recursions) + '""' + ('}' * num_recursions)
    token = generate_token('{"alg":"HS256"}', payload)
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)

if __name__ == '__main__':
  absltest.main()
