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

# Placeholder for import for type annotations

import base64
import datetime

from typing import Text

from absl.testing import absltest
from absl.testing import parameterized

import tink
from tink import cleartext_keyset_handle
from tink import mac

from tink.proto import common_pb2
from tink.proto import hmac_pb2
from tink.proto import jwt_hmac_pb2
from tink.proto import tink_pb2
from tink import jwt
from tink.jwt import _jwt_format
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
EMPTY_VALIDATOR = jwt.new_validator()


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


def generate_token_from_bytes(header: bytes, payload: bytes) -> Text:
  """Generates tokens from bytes with valid MACs."""
  unsigned_compact = (
      _jwt_format._base64_encode(header) + b'.' +
      _jwt_format._base64_encode(payload))
  mac_value = MAC.compute_mac(unsigned_compact)
  return (unsigned_compact + b'.' +
          _jwt_format.encode_signature(mac_value)).decode('utf8')


def generate_token(header: Text, payload: Text) -> Text:
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
    token = generate_token('{"alg":"HS256"}', '{"iss":"joe"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    verified_jwt = jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)
    self.assertEqual(verified_jwt.issuer(), 'joe')

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_unknown_header_valid(self, lang):
    token = generate_token('{"alg":"HS256", "unknown":{"a":"b"}}',
                           '{"iss":"joe"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    verified_jwt = jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)
    self.assertEqual(verified_jwt.issuer(), 'joe')

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_empty_crit_header_invalid(self, lang):
    # See https://tools.ietf.org/html/rfc7515#section-4.1.11
    token = generate_token('{"alg":"HS256", "crit":[]}', '{"iss":"joe"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_nonempty_crit_header_invalid(self, lang):
    # See https://tools.ietf.org/html/rfc7515#section-4.1.11
    token = generate_token(
        '{"alg":"HS256","crit":["http://example.invalid/UNDEFINED"],'
        '"http://example.invalid/UNDEFINED":true}', '{"iss":"joe"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_unknown_typ_header_valid(self, lang):
    token = generate_token('{"typ":"unknown", "alg":"HS256"}', '{"iss":"joe"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    verified_jwt = jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)
    self.assertEqual(verified_jwt.type_header(), 'unknown')

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_expiration(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"iss":"joe", "exp":1234}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    # same time is expired.
    val1 = jwt.new_validator(
        fixed_now=datetime.datetime.fromtimestamp(1234, datetime.timezone.utc))
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, val1)

    # a fraction of a second before is fine
    val2 = jwt.new_validator(
        fixed_now=datetime.datetime.fromtimestamp(1233.75,
                                                  datetime.timezone.utc))
    jwt_mac.verify_mac_and_decode(token, val2)

    # 3 seconds too late with 3 seconds clock skew is expired.
    val4 = jwt.new_validator(
        fixed_now=datetime.datetime.fromtimestamp(1237, datetime.timezone.utc),
        clock_skew=datetime.timedelta(seconds=3))
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, val4)

    # 2 seconds too late with 3 seconds clock skew is fine.
    val3 = jwt.new_validator(
        fixed_now=datetime.datetime.fromtimestamp(1236, datetime.timezone.utc),
        clock_skew=datetime.timedelta(seconds=3))
    jwt_mac.verify_mac_and_decode(token, val3)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_float_expiration(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"iss":"joe", "exp":1234.5}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    # same time is expired.
    val1 = jwt.new_validator(
        fixed_now=datetime.datetime.fromtimestamp(1234.5,
                                                  datetime.timezone.utc))
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, val1)

    # a fraction of a second after is expired.
    val1 = jwt.new_validator(
        fixed_now=datetime.datetime.fromtimestamp(1234.75,
                                                  datetime.timezone.utc))
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, val1)

    # a fraction of a second before is fine
    val2 = jwt.new_validator(
        fixed_now=datetime.datetime.fromtimestamp(1234.25,
                                                  datetime.timezone.utc))
    jwt_mac.verify_mac_and_decode(token, val2)

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
    token = generate_token('{"alg":"HS256"}', '{"iss":"joe", "exp":Infinity}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_not_before(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"iss":"joe", "nbf":1234}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    # same time as nbf fine.
    val1 = jwt.new_validator(
        fixed_now=datetime.datetime.fromtimestamp(1234, datetime.timezone.utc))
    jwt_mac.verify_mac_and_decode(token, val1)

    # one second before is not yet valid
    val2 = jwt.new_validator(
        fixed_now=datetime.datetime.fromtimestamp(1233, datetime.timezone.utc))
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, val2)

    # 3 seconds too early with 3 seconds clock skew is fine
    val4 = jwt.new_validator(
        fixed_now=datetime.datetime.fromtimestamp(1231, datetime.timezone.utc),
        clock_skew=datetime.timedelta(seconds=3))
    jwt_mac.verify_mac_and_decode(token, val4)

    # 3 seconds too late with 2 seconds clock skew is fine.
    val3 = jwt.new_validator(
        fixed_now=datetime.datetime.fromtimestamp(1231, datetime.timezone.utc),
        clock_skew=datetime.timedelta(seconds=2))
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, val3)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_float_not_before(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"iss":"joe", "nbf":1234.5}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    val1 = jwt.new_validator(
        fixed_now=datetime.datetime.fromtimestamp(1234, datetime.timezone.utc))
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, val1)

    val2 = jwt.new_validator(
        fixed_now=datetime.datetime.fromtimestamp(1235, datetime.timezone.utc))
    jwt_mac.verify_mac_and_decode(token, val2)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_issuer(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"iss":"joe"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    val1 = jwt.new_validator(issuer='joe')
    jwt_mac.verify_mac_and_decode(token, val1)

    val2 = EMPTY_VALIDATOR
    jwt_mac.verify_mac_and_decode(token, val2)

    val3 = jwt.new_validator(issuer='Joe')
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, val3)

    val4 = jwt.new_validator(issuer='joe ')
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, val4)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_empty_string_issuer(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"iss":""}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    jwt_mac.verify_mac_and_decode(token, jwt.new_validator(issuer=''))

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
    token = generate_token_from_bytes(b'{"alg":"HS256"}', b'{"iss":"joe\xc2"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_with_utf16_surrogate_in_payload(self, lang):
    # The JSON string contains the G clef character (U+1D11E) in UTF8.
    token = generate_token_from_bytes(b'{"alg":"HS256"}',
                                      b'{"iss":"\xF0\x9D\x84\x9E"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    token = jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)
    self.assertEqual(token.issuer(), u'\U0001d11e')

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_with_json_escaped_utf16_surrogate_in_payload(self, lang):
    # The JSON string contains "\uD834\uDD1E", which should decode to
    # the G clef character (U+1D11E).
    token = generate_token('{"alg":"HS256"}', '{"iss":"\\uD834\\uDD1E"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    token = jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)
    self.assertEqual(token.issuer(), u'\U0001d11e')

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_with_invalid_json_escaped_utf16_in_payload(self, lang):
    # The JSON string contains "\uD834", which gets decoded into an invalid
    # UTF16 character.
    token = generate_token('{"alg":"HS256"}', '{"iss":"\\uD834"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_subject(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"sub":"joe"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    val1 = jwt.new_validator(subject='joe')
    jwt_mac.verify_mac_and_decode(token, val1)

    val2 = EMPTY_VALIDATOR
    jwt_mac.verify_mac_and_decode(token, val2)

    val3 = jwt.new_validator(subject='Joe')
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, val3)

    val4 = jwt.new_validator(subject='joe ')
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, val4)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_empty_string_subject(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"sub":""}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    jwt_mac.verify_mac_and_decode(token, jwt.new_validator(subject=''))

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_subject_with_wrong_type(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"sub":123}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_audience(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"aud":["joe", "jane"]}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    val1 = jwt.new_validator(audience='joe')
    jwt_mac.verify_mac_and_decode(token, val1)

    val2 = jwt.new_validator(audience='jane')
    jwt_mac.verify_mac_and_decode(token, val2)

    val3 = EMPTY_VALIDATOR
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, val3)

    val4 = jwt.new_validator(audience='Joe')
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, val4)

    val5 = jwt.new_validator(audience='jane ')
    with self.assertRaises(tink.TinkError):
      jwt_mac.verify_mac_and_decode(token, val5)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_audience_string(self, lang):
    token = generate_token('{"alg":"HS256"}', '{"aud":"joe"}')
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)

    val1 = jwt.new_validator(audience='joe')
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
  def test_verify_token_with_many_recursions(self, lang):
    num_recursions = 10
    payload = ('{"a":' * num_recursions) + '""' + ('}' * num_recursions)
    token = generate_token('{"alg":"HS256"}', payload)
    jwt_mac = testing_servers.jwt_mac(lang, KEYSET)
    jwt_mac.verify_mac_and_decode(token, EMPTY_VALIDATOR)

  @parameterized.parameters(SUPPORTED_LANGUAGES)
  def test_verify_token_with_too_many_recursions_fails(self, lang):
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
