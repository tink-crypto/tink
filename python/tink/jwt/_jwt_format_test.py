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
"""Tests for tink.python.tink.jwt._jwt_format."""

from absl.testing import absltest
from absl.testing import parameterized
from tink.proto import tink_pb2
from tink.jwt import _jwt_error
from tink.jwt import _jwt_format


class JwtFormatTest(parameterized.TestCase):

  def test_base64_encode_decode_header_fixed_data(self):
    # Example from https://tools.ietf.org/html/rfc7519#section-3.1
    header = bytes([
        123, 34, 116, 121, 112, 34, 58, 34, 74, 87, 84, 34, 44, 13, 10, 32, 34,
        97, 108, 103, 34, 58, 34, 72, 83, 50, 53, 54, 34, 125
    ])
    encoded_header = b'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'
    self.assertEqual(_jwt_format._base64_encode(header), encoded_header)
    self.assertEqual(_jwt_format._base64_decode(encoded_header), header)

  def test_base64_encode_decode_payload_fixed_data(self):
    # Example from https://tools.ietf.org/html/rfc7519#section-3.1
    payload = bytes([
        123, 34, 105, 115, 115, 34, 58, 34, 106, 111, 101, 34, 44, 13, 10, 32,
        34, 101, 120, 112, 34, 58, 49, 51, 48, 48, 56, 49, 57, 51, 56, 48, 44,
        13, 10, 32, 34, 104, 116, 116, 112, 58, 47, 47, 101, 120, 97, 109, 112,
        108, 101, 46, 99, 111, 109, 47, 105, 115, 95, 114, 111, 111, 116, 34,
        58, 116, 114, 117, 101, 125
    ])
    encoded_payload = (b'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0'
                       b'dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ')
    self.assertEqual(_jwt_format._base64_encode(payload), encoded_payload)
    self.assertEqual(_jwt_format._base64_decode(encoded_payload), payload)

  def test_base64_decode_bad_format_raises_jwt_invalid_error(self):
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format._base64_decode(b'aeyJh')

  def test_base64_decode_fails_with_unknown_chars(self):
    self.assertNotEmpty(
        _jwt_format._base64_decode(
            b'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-')
    )
    self.assertEqual(_jwt_format._base64_decode(b''), b'')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format._base64_decode(b'[')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format._base64_decode(b'@')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format._base64_decode(b'/')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format._base64_decode(b':')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format._base64_decode(b'{')

  def test_json_loads_recursion(self):
    num_recursions = 1000
    recursive_json = ('{"a":' * num_recursions) + '""' + ('}' * num_recursions)
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.json_loads(recursive_json)

  def test_json_loads_with_invalid_utf16(self):
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.json_loads(u'{"a":{"b":{"c":"\\uD834"}}}')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.json_loads(u'{"\\uD834":"b"}')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.json_loads(u'{"a":["a":{"b":["c","\\uD834"]}]}')

  def test_decode_encode_header_hs256(self):
    # Example from https://tools.ietf.org/html/rfc7515#appendix-A.1
    encoded_header = b'eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9'
    json_header = _jwt_format.decode_header(encoded_header)
    header = _jwt_format.json_loads(json_header)
    self.assertEqual(header['alg'], 'HS256')
    self.assertEqual(header['typ'], 'JWT')
    self.assertEqual(
        _jwt_format.decode_header(_jwt_format.encode_header(json_header)),
        json_header)

  def test_decode_encode_header_rs256(self):
    # Example from https://tools.ietf.org/html/rfc7515#appendix-A.2
    encoded_header = b'eyJhbGciOiJSUzI1NiJ9'
    json_header = _jwt_format.decode_header(encoded_header)
    header = _jwt_format.json_loads(json_header)
    self.assertEqual(header['alg'], 'RS256')
    self.assertEqual(
        _jwt_format.decode_header(_jwt_format.encode_header(json_header)),
        json_header)

  def test_encode_decode_header(self):
    encoded_header = _jwt_format.encode_header('{ "alg": "RS256"} ')
    json_header = _jwt_format.decode_header(encoded_header)
    self.assertEqual(json_header, '{ "alg": "RS256"} ')

  def test_decode_header_with_invalid_utf8(self):
    encoded_header = _jwt_format._base64_encode(
        b'{"alg":"RS256", "bad":"\xc2"}')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.decode_header(encoded_header)

  def test_encode_header_with_utf16_surrogate(self):
    self.assertEqual(
        _jwt_format.encode_header('{"alg": "RS256", "a":"\U0001d11e"}'),
        b'eyJhbGciOiAiUlMyNTYiLCAiYSI6IvCdhJ4ifQ')

  def test_encode_header_with_invalid_utf16_character(self):
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.encode_header('{"alg": "RS256", "a":"\uD834"}')

  @parameterized.parameters([
      'HS256', 'HS384', 'HS512', 'ES256', 'ES384', 'ES512', 'RS256', 'RS384',
      'RS384', 'RS512', 'PS256', 'PS384', 'PS512'
  ])
  def test_create_validate_header(self, algorithm):
    encoded_header = _jwt_format.create_header(algorithm, None, None)
    json_header = _jwt_format.decode_header(encoded_header)
    header = _jwt_format.json_loads(json_header)
    _jwt_format.validate_header(header, algorithm)
    self.assertIsNone(_jwt_format.get_type_header(header))

  def test_create_header_with_type(self):
    encoded_header = _jwt_format.create_header('HS256', 'typeHeader', None)
    json_header = _jwt_format.decode_header(encoded_header)
    self.assertEqual(json_header, '{"alg":"HS256","typ":"typeHeader"}')
    header = _jwt_format.json_loads(json_header)
    _jwt_format.validate_header(header, 'HS256')
    self.assertEqual(_jwt_format.get_type_header(header), 'typeHeader')

  def test_create_header_with_type_and_kid(self):
    encoded_header = _jwt_format.create_header('HS256', 'typeHeader', 'GsapRA')
    json_header = _jwt_format.decode_header(encoded_header)
    self.assertEqual(json_header,
                     '{"kid":"GsapRA","alg":"HS256","typ":"typeHeader"}')
    header = _jwt_format.json_loads(json_header)
    _jwt_format.validate_header(header, 'HS256')
    self.assertEqual(_jwt_format.get_type_header(header), 'typeHeader')

  def test_create_header_with_unknown_alg_fails(self):
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.create_header('unknown', None, None)

  def test_create_verify_different_algorithms_fails(self):
    encoded_header = _jwt_format.create_header('HS256', None, None)
    json_header = _jwt_format.decode_header(encoded_header)
    header = _jwt_format.json_loads(json_header)
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.validate_header(header, 'ES256')

  def test_verify_empty_header_fails(self):
    header = _jwt_format.json_loads('{}')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.validate_header(header, 'ES256')

  def test_validate_header_with_unknown_algorithm_fails(self):
    header = _jwt_format.json_loads('{"alg":"HS123"}')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.validate_header(header, 'HS123')

  def test_validate_header_with_unknown_entry_success(self):
    header = _jwt_format.json_loads('{"alg":"HS256","unknown":"header"}')
    _jwt_format.validate_header(header, 'HS256')

  def test_validate_header_ignores_typ(self):
    header = _jwt_format.json_loads('{"alg":"HS256","typ":"unknown"}')
    _jwt_format.validate_header(header, 'HS256')

  def test_validate_header_rejects_crit(self):
    header = _jwt_format.json_loads(
        '{"alg":"HS256","crit":["http://example.invalid/UNDEFINED"],'
        '"http://example.invalid/UNDEFINED":true}')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.validate_header(header, 'HS256')

  def test_get_kid_success(self):
    key_id = 0x1ac6a944
    self.assertEqual(_jwt_format.get_kid(key_id, tink_pb2.TINK), 'GsapRA')
    self.assertIsNone(_jwt_format.get_kid(key_id, tink_pb2.RAW), None)
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.get_kid(key_id, tink_pb2.LEGACY)

  def test_get_kid_invalid_input_fails(self):
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.get_kid(123, tink_pb2.LEGACY)
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.get_kid(-1, tink_pb2.TINK)
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.get_kid(2**33, tink_pb2.TINK)

  def test_json_decode_encode_payload_fixed_data(self):
    # Example from https://tools.ietf.org/html/rfc7519#section-3.1
    encoded_payload = (b'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0'
                       b'dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ')
    json_payload = _jwt_format.decode_payload(encoded_payload)
    payload = _jwt_format.json_loads(json_payload)
    self.assertEqual(payload['iss'], 'joe')
    self.assertEqual(payload['exp'], 1300819380)
    self.assertEqual(payload['http://example.com/is_root'], True)
    self.assertEqual(
        _jwt_format.decode_payload(_jwt_format.encode_payload(json_payload)),
        json_payload)

  def test_decode_encode_payload(self):
    # Example from https://tools.ietf.org/html/rfc7519#section-3.1
    encoded_payload = (b'eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0'
                       b'dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ')
    json_payload = _jwt_format.decode_payload(encoded_payload)
    payload = _jwt_format.json_loads(json_payload)
    self.assertEqual(payload['iss'], 'joe')
    self.assertEqual(payload['exp'], 1300819380)
    self.assertEqual(payload['http://example.com/is_root'], True)
    self.assertEqual(
        _jwt_format.decode_payload(_jwt_format.encode_payload(json_payload)),
        json_payload)

  def test_encode_payload_with_utf16_surrogate(self):
    self.assertEqual(
        _jwt_format.encode_payload('{"iss":"\U0001d11e"}'),
        b'eyJpc3MiOiLwnYSeIn0')

  def test_encode_payload_with_invalid_utf16(self):
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.encode_payload('{"iss":"\uD834"}')

  def test_create_unsigned_compact_success(self):
    self.assertEqual(
        _jwt_format.create_unsigned_compact('RS256', None, None,
                                            '{"iss":"joe"}'),
        b'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UifQ')

  def test_encode_decode_signature_success(self):
    signature = bytes([
        116, 24, 223, 180, 151, 153, 224, 37, 79, 250, 96, 125, 216, 173, 187,
        186, 22, 212, 37, 77, 105, 214, 191, 240, 91, 88, 5, 88, 83, 132, 141,
        121
    ])
    encoded = _jwt_format.encode_signature(signature)
    self.assertEqual(encoded, b'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')
    self.assertEqual(_jwt_format.decode_signature(encoded), signature)

  def test_signed_compact_create_split(self):
    payload = '{"iss":"joe"}'
    signature = _jwt_format.decode_signature(
        b'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')
    unsigned_compact = _jwt_format.create_unsigned_compact(
        'RS256', 'JWT', None, payload)
    signed_compact = _jwt_format.create_signed_compact(unsigned_compact,
                                                       signature)
    un_comp, hdr, pay, sig = _jwt_format.split_signed_compact(signed_compact)

    self.assertEqual(
        unsigned_compact,
        b'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJqb2UifQ')
    self.assertEqual(
        signed_compact, 'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.'
        'eyJpc3MiOiJqb2UifQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')
    self.assertEqual(un_comp, unsigned_compact)
    self.assertEqual(sig, signature)
    self.assertEqual(hdr, '{"alg":"RS256","typ":"JWT"}')
    header = _jwt_format.json_loads(hdr)
    _jwt_format.validate_header(header, 'RS256')
    self.assertEqual(pay, payload)
    self.assertEqual(_jwt_format.get_type_header(header), 'JWT')

  def test_signed_compact_create_split_with_kid(self):
    payload = '{"iss":"joe"}'
    signature = _jwt_format.decode_signature(
        b'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')
    unsigned_compact = _jwt_format.create_unsigned_compact(
        'RS256', None, 'AZxkm2U', payload)
    signed_compact = _jwt_format.create_signed_compact(unsigned_compact,
                                                       signature)
    un_comp, hdr, pay, sig = _jwt_format.split_signed_compact(signed_compact)

    self.assertEqual(
        unsigned_compact,
        b'eyJraWQiOiJBWnhrbTJVIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJqb2UifQ')
    self.assertEqual(
        signed_compact,
        'eyJraWQiOiJBWnhrbTJVIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJqb2UifQ'
        '.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')
    self.assertEqual(un_comp, unsigned_compact)
    self.assertEqual(sig, signature)
    self.assertEqual(hdr, '{"kid":"AZxkm2U","alg":"RS256"}')
    header = _jwt_format.json_loads(hdr)
    _jwt_format.validate_header(header, 'RS256')
    self.assertEqual(pay, payload)
    self.assertIsNone(_jwt_format.get_type_header(header))

  def test_split_empty_signed_compact(self):
    un_comp, hdr, pay, sig = _jwt_format.split_signed_compact('..')
    self.assertEqual(un_comp, b'.')
    self.assertEmpty(sig)
    self.assertEmpty(hdr)
    self.assertEmpty(pay)

  def test_split_signed_compact_success(self):
    un_comp, hdr, pay, sig = _jwt_format.split_signed_compact('e30.e30.YWJj')
    self.assertEqual(un_comp, b'e30.e30')
    self.assertEqual(sig, b'abc')
    self.assertEqual(hdr, '{}')
    self.assertEqual(pay, '{}')

  def test_split_signed_compact_with_bad_format_fails(self):
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.split_signed_compact('e30.e30.YWJj.abc')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.split_signed_compact('e30.e30.YWJj.')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.split_signed_compact('.e30.e30.YWJj')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.split_signed_compact('.e30.e30.')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.split_signed_compact('e30')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.split_signed_compact('')

  def test_split_signed_compact_with_bad_characters_fails(self):
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.split_signed_compact('{e30.e30.YWJj')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.split_signed_compact(' e30.e30.YWJj')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.split_signed_compact('e30. e30.YWJj')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.split_signed_compact('e30.e30.YWJj ')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.split_signed_compact('e30.e30.\nYWJj')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.split_signed_compact('e30.\re30.YWJj')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.split_signed_compact('e30$.e30.YWJj')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.split_signed_compact('e30.$e30.YWJj')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.split_signed_compact('e30.e30.YWJj$')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.split_signed_compact('e30.e30.YWJj\ud83c')

  def test_split_signed_compact_with_invalid_utf8_in_header(self):
    encoded_header = _jwt_format._base64_encode(
        b'{"alg":"RS256", "bad":"\xc2"}')
    token = (encoded_header + b'.e30.YWJj').decode('utf8')
    with self.assertRaises(_jwt_error.JwtInvalidError):
      _jwt_format.split_signed_compact(token)


if __name__ == '__main__':
  absltest.main()
