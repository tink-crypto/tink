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
import json

from typing import Any, Text

from tink.jwt import _raw_jwt

_VALID_ALGORITHMS = frozenset({
    'HS256', 'HS384', 'HS512', 'ES256', 'ES384', 'ES512', 'RS256', 'RS384',
    'RS384', 'RS512', 'PS256', 'PS384', 'PS512'
})


def _base64_encode(data: bytes) -> bytes:
  data = base64.urlsafe_b64encode(data)
  while data and data[-1] == ord('='):
    data = data[:-1]
  return data


def _base64_decode(encoded_data: bytes) -> bytes:
  padded_encoded_data = encoded_data + b'=' * (-len(encoded_data) % 4)
  return base64.urlsafe_b64decode(padded_encoded_data)


def _json_encode(json_data: Any) -> bytes:
  json_text = json.dumps(json_data, separators=(',', ':'))
  return _base64_encode(json_text.encode('utf8'))


def _json_decode(data: bytes) -> Any:
  try:
    return json.loads(_base64_decode(data))
  except json.decoder.JSONDecodeError:
    raise _raw_jwt.JwtInvalidError('Failed to parse JSON string')


def _validate_algorithm(algorithm: Text) -> None:
  if algorithm not in _VALID_ALGORITHMS:
    raise _raw_jwt.JwtInvalidError('Invalid algorithm %s' % algorithm)


def encode_payload(payload: Any) -> bytes:
  """Encodes the payload into compact form."""
  return _json_encode(payload)


def decode_payload(encoded_payload: bytes) -> Any:
  """Decodes the payload from compact form."""
  return _json_decode(encoded_payload)


def encode_signature(signature: bytes) -> bytes:
  """Encodes the signature."""
  return _base64_encode(signature)


def decode_signature(encoded_signature: bytes) -> bytes:
  """Decodes the signature."""
  return _base64_decode(encoded_signature)


def create_header(algorithm: Text) -> bytes:
  _validate_algorithm(algorithm)
  return _json_encode({'alg': algorithm})


def validate_header(header: bytes, algorithm: Text) -> None:
  """Parses the header and validates its values."""
  _validate_algorithm(algorithm)
  decoded_header = _json_decode(header)
  hdr_algorithm = decoded_header.get('alg', '')
  if hdr_algorithm.upper() != algorithm:
    raise _raw_jwt.JwtInvalidError('Invalid algorithm; expected %s, got %s' %
                                   (algorithm, hdr_algorithm))
  header_type = decoded_header.get('typ', None)
  if 'typ' in decoded_header:
    if decoded_header['typ'].upper() != 'JWT':
      raise _raw_jwt.JwtInvalidError(
          'Invalid header type; expected JWT, got %s' % decoded_header['typ'])


def create_unsigned_compact(algorithm: Text, payload: Any) -> bytes:
  return create_header(algorithm) + b'.' + encode_payload(payload)


def create_signed_compact(unsigned_compact: bytes, signature: bytes) -> Text:
  return (unsigned_compact + b'.' + encode_signature(signature)).decode('utf8')
