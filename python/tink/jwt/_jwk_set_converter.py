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
"""Convert Tink Keyset with JWT keys from and to JWK sets."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import io
import json
from typing import Dict, List, Optional, Text, Union

from tink.proto import jwt_ecdsa_pb2
from tink.proto import tink_pb2
import tink
from tink.jwt import _jwt_format

_JWT_ECDSA_PRIVATE_KEY_TYPE = (
    'type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey')
_JWT_ECDSA_PUBLIC_KEY_TYPE = (
    'type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey')

_ECDSA_ALGORITHM_TEXTS = {
    jwt_ecdsa_pb2.ES256: 'ES256',
    jwt_ecdsa_pb2.ES384: 'ES384',
    jwt_ecdsa_pb2.ES512: 'ES512'
}


def _base64_encode(data: bytes) -> Text:
  return _jwt_format.base64_encode(data).decode('utf8')


def from_keyset_handle(keyset_handle: tink.KeysetHandle,
                       key_access: Optional[tink.KeyAccess] = None) -> Text:
  """Converts a Tink KeysetHandle with JWT keys into a Json Web Key (JWK) set.

  JWK is defined in https://www.rfc-editor.org/rfc/rfc7517.txt.

  Disabled keys are skipped.

  Keys with output prefix type "TINK" will include the encoded key ID as "kid"
  value. Keys with output prefix type "RAW" will not have a "kid" value set.

  Currently, only public keys for algorithms ES256, ES384 and ES512 are
  supported.

  Args:
    keyset_handle: A Tink KeysetHandle that contains JWT Keys.
    key_access: An optional KeyAccess object. Currently not needed.

  Returns:
    A JWK set, which is a JSON encoded string.

  Raises:
    TinkError if the keys are not of the expected type, or if they have a
    ouput prefix type that is not supported.
  """
  output_stream = io.BytesIO()
  writer = tink.BinaryKeysetWriter(output_stream)
  _ = key_access  # currently not used, since we only support public keys.
  keyset_handle.write_no_secret(writer)
  keyset = tink_pb2.Keyset.FromString(output_stream.getvalue())

  keys = []
  for key in keyset.key:
    if key.status != tink_pb2.ENABLED:
      continue
    if key.key_data.key_material_type != tink_pb2.KeyData.ASYMMETRIC_PUBLIC:
      raise tink.TinkError('wrong key material type')
    if key.output_prefix_type not in [tink_pb2.RAW, tink_pb2.TINK]:
      raise tink.TinkError('unsupported output prefix type')
    if key.key_data.type_url == _JWT_ECDSA_PUBLIC_KEY_TYPE:
      keys.append(_convert_jwt_ecdsa_key(key))
    else:
      raise tink.TinkError('unknown key type')
  return json.dumps({'keys': keys}, separators=(',', ':'))


def _convert_jwt_ecdsa_key(
    key: tink_pb2.Keyset.Key) -> Dict[Text, Union[Text, List[Text]]]:
  """Converts a JwtEcdsaPublicKey into a JWK."""
  ecdsa_public_key = jwt_ecdsa_pb2.JwtEcdsaPublicKey.FromString(
      key.key_data.value)
  if ecdsa_public_key.algorithm == jwt_ecdsa_pb2.ES256:
    alg = 'ES256'
    crv = 'P-256'
  elif ecdsa_public_key.algorithm == jwt_ecdsa_pb2.ES384:
    alg = 'ES384'
    crv = 'P-384'
  elif ecdsa_public_key.algorithm == jwt_ecdsa_pb2.ES512:
    alg = 'ES512'
    crv = 'P-521'
  else:
    raise tink.TinkError('unknown ecdsa algorithm')
  output = {
      'kty': 'EC',
      'crv': crv,
      'x': _base64_encode(ecdsa_public_key.x),
      'y': _base64_encode(ecdsa_public_key.y),
      'use': 'sig',
      'alg': alg,
      'key_ops': ['verify'],
  }
  kid = _jwt_format.get_kid(key.key_id, key.output_prefix_type)
  if kid:
    output['kid'] = kid
  elif ecdsa_public_key.HasField('custom_kid'):
    output['kid'] = ecdsa_public_key.custom_kid.value
  return output
