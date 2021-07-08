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
"""Functions that help to serialize and deserialize from/to the JWT format."""

import base64
import binascii
import json
import struct
from typing import Any, Optional, Text, Tuple

from tink.proto import tink_pb2
from tink.jwt import _jwt_error

_VALID_ALGORITHMS = frozenset({
    'HS256', 'HS384', 'HS512', 'ES256', 'ES384', 'ES512', 'RS256', 'RS384',
    'RS384', 'RS512', 'PS256', 'PS384', 'PS512'
})


def _base64_encode(data: bytes) -> bytes:
  """Does a URL-safe base64 encoding without padding."""
  return base64.urlsafe_b64encode(data).rstrip(b'=')


def _is_valid_urlsafe_base64_char(c: int) -> bool:
  if c >= ord('a') and c <= ord('z'):
    return True
  if c >= ord('A') and c <= ord('Z'):
    return True
  if c >= ord('0') and c <= ord('9'):
    return True
  if c == ord('-') or c == ord('_'):
    return True
  return False


def _base64_decode(encoded_data: bytes) -> bytes:
  """Does a URL-safe base64 decoding without padding."""
  # base64.urlsafe_b64decode ignores all non-base64 chars. We don't want that.
  for c in encoded_data:
    if not _is_valid_urlsafe_base64_char(c):
      raise _jwt_error.JwtInvalidError('invalid token')
  # base64.urlsafe_b64decode requires padding, but does not mind too much
  # padding. So we simply add the maximum ammount of padding needed.
  padded_encoded_data = encoded_data + b'==='
  try:
    return base64.urlsafe_b64decode(padded_encoded_data)
  except binascii.Error:
    # Throws when the length of encoded_data is (4*i + 1) for some i
    raise _jwt_error.JwtInvalidError('invalid token')


def json_dumps(json_data: Any) -> Text:
  return json.dumps(json_data, separators=(',', ':'))


def validate_all_strings(json_data: Any):
  """Recursivly visits all strings and raises UnicodeEncodeError if invalid."""
  if isinstance(json_data, str):
    # We use encode('utf8') to validate that the string is valid.
    json_data.encode('utf8')
  if isinstance(json_data, list):
    for item in json_data:
      validate_all_strings(item)
  if isinstance(json_data, dict):
    for key, value in json_data.items():
      key.encode('utf8')
      validate_all_strings(value)


def json_loads(json_text: Text) -> Any:
  """Does the same as json.loads, but with some additinal validation."""
  try:
    json_data = json.loads(json_text)
    validate_all_strings(json_data)
    return json_data
  except json.decoder.JSONDecodeError:
    raise _jwt_error.JwtInvalidError('Failed to parse JSON string')
  except RecursionError:
    raise _jwt_error.JwtInvalidError(
        'Failed to parse JSON string, too many recursions')
  except UnicodeEncodeError:
    raise _jwt_error.JwtInvalidError('invalid character')


def _validate_algorithm(algorithm: Text) -> None:
  if algorithm not in _VALID_ALGORITHMS:
    raise _jwt_error.JwtInvalidError('Invalid algorithm %s' % algorithm)


def encode_header(json_header: Text) -> bytes:
  try:
    return _base64_encode(json_header.encode('utf8'))
  except UnicodeEncodeError:
    raise _jwt_error.JwtInvalidError('invalid token')


def decode_header(encoded_header: bytes) -> Text:
  try:
    return _base64_decode(encoded_header).decode('utf8')
  except UnicodeDecodeError:
    raise _jwt_error.JwtInvalidError('invalid token')


def encode_payload(json_payload: Text) -> bytes:
  """Encodes the payload into compact form."""
  try:
    return _base64_encode(json_payload.encode('utf8'))
  except UnicodeEncodeError:
    raise _jwt_error.JwtInvalidError('invalid token')


def decode_payload(encoded_payload: bytes) -> Text:
  """Decodes the payload from compact form."""
  try:
    return _base64_decode(encoded_payload).decode('utf8')
  except UnicodeDecodeError:
    raise _jwt_error.JwtInvalidError('invalid token')


def encode_signature(signature: bytes) -> bytes:
  """Encodes the signature."""
  return _base64_encode(signature)


def decode_signature(encoded_signature: bytes) -> bytes:
  """Decodes the signature."""
  return _base64_decode(encoded_signature)


def create_header(algorithm: Text, type_header: Optional[Text],
                  kid: Optional[Text]) -> bytes:
  _validate_algorithm(algorithm)
  header = {}
  if kid:
    header['kid'] = kid
  header['alg'] = algorithm
  if type_header:
    header['typ'] = type_header
  return encode_header(json_dumps(header))


def get_kid(key_id: int, prefix: tink_pb2.OutputPrefixType) -> Optional[Text]:
  """Returns the encoded key_id, or None."""
  if prefix == tink_pb2.RAW:
    return None
  if prefix == tink_pb2.TINK:
    if key_id < 0 or key_id > 2**32:
      raise _jwt_error.JwtInvalidError('invalid key_id')
    return _base64_encode(struct.pack('>L', key_id)).decode('utf8')
  raise _jwt_error.JwtInvalidError('unexpected output prefix type')


def split_signed_compact(
    signed_compact: Text) -> Tuple[bytes, Text, Text, bytes]:
  """Splits a signed compact into its parts.

  Args:
    signed_compact: A signed compact JWT.
  Returns:
    A (unsigned_compact, json_header, json_payload, signature_or_mac) tuple.
  Raises:
    _jwt_error.JwtInvalidError if it fails.
  """
  try:
    encoded = signed_compact.encode('utf8')
  except UnicodeEncodeError:
    raise _jwt_error.JwtInvalidError('invalid token')
  try:
    unsigned_compact, encoded_signature = encoded.rsplit(b'.', 1)
  except ValueError:
    raise _jwt_error.JwtInvalidError('invalid token')
  signature_or_mac = decode_signature(encoded_signature)
  try:
    encoded_header, encoded_payload = unsigned_compact.split(b'.')
  except ValueError:
    raise _jwt_error.JwtInvalidError('invalid token')

  json_header = decode_header(encoded_header)
  json_payload = decode_payload(encoded_payload)
  return (unsigned_compact, json_header, json_payload, signature_or_mac)


def validate_header(header: Any, algorithm: Text) -> None:
  """Parses the header and validates its values."""
  _validate_algorithm(algorithm)
  hdr_algorithm = header.get('alg', '')
  if hdr_algorithm.upper() != algorithm:
    raise _jwt_error.JwtInvalidError('Invalid algorithm; expected %s, got %s' %
                                     (algorithm, hdr_algorithm))
  if 'crit' in header:
    raise _jwt_error.JwtInvalidError(
        'all tokens with crit headers are rejected')


def get_type_header(header: Any) -> Optional[Text]:
  return header.get('typ', None)


# TODO(juerg): Refactor this to create_unsigned_compact(algorithm, kid, raw_jwt)
def create_unsigned_compact(algorithm: Text, typ_header: Optional[Text],
                            kid: Optional[Text], json_payload: Text) -> bytes:
  header = create_header(algorithm, typ_header, kid)
  return header + b'.' + encode_payload(json_payload)


def create_signed_compact(unsigned_compact: bytes, signature: bytes) -> Text:
  return (unsigned_compact + b'.' + encode_signature(signature)).decode('utf8')
