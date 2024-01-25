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

import json
import random

from typing import cast, Dict, List, Optional, Union

from tink.proto import jwt_ecdsa_pb2
from tink.proto import jwt_rsa_ssa_pkcs1_pb2
from tink.proto import jwt_rsa_ssa_pss_pb2
from tink.proto import tink_pb2
import tink
from tink.jwt import _jwt_format

_JWT_ECDSA_PUBLIC_KEY_TYPE = (
    'type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey')
_JWT_RSA_SSA_PKCS1_PUBLIC_KEY_TYPE = (
    'type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey')
_JWT_RSA_SSA_PSS_PUBLIC_KEY_TYPE = (
    'type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey')

_ECDSA_PARAMS = {
    jwt_ecdsa_pb2.ES256: ('ES256', 'P-256'),
    jwt_ecdsa_pb2.ES384: ('ES384', 'P-384'),
    jwt_ecdsa_pb2.ES512: ('ES512', 'P-521')
}

_ECDSA_NAME_TO_ALGORITHM = {
    alg_name: algorithm for algorithm, (alg_name, _) in _ECDSA_PARAMS.items()
}

_RSA_SSA_PKCS1_PARAMS = {
    jwt_rsa_ssa_pkcs1_pb2.RS256: 'RS256',
    jwt_rsa_ssa_pkcs1_pb2.RS384: 'RS384',
    jwt_rsa_ssa_pkcs1_pb2.RS512: 'RS512'
}

_RSA_SSA_PKCS1_NAME_TO_ALGORITHM = {
    alg_name: algorithm
    for algorithm, alg_name in _RSA_SSA_PKCS1_PARAMS.items()
}

_RSA_SSA_PSS_PARAMS = {
    jwt_rsa_ssa_pss_pb2.PS256: 'PS256',
    jwt_rsa_ssa_pss_pb2.PS384: 'PS384',
    jwt_rsa_ssa_pss_pb2.PS512: 'PS512'
}

_RSA_SSA_PSS_NAME_TO_ALGORITHM = {
    alg_name: algorithm
    for algorithm, alg_name in _RSA_SSA_PSS_PARAMS.items()
}


def _base64_encode(data: bytes) -> str:
  return _jwt_format.base64_encode(data).decode('utf8')


def _base64_decode(data: str) -> bytes:
  return _jwt_format.base64_decode(data.encode('utf8'))


def from_public_keyset_handle(keyset_handle: tink.KeysetHandle) -> str:
  """Converts a Tink KeysetHandle with JWT keys into a Json Web Key (JWK) set.

  JWK is defined in https://www.rfc-editor.org/rfc/rfc7517.txt.

  Disabled keys are skipped.

  Keys with output prefix type "TINK" will include the encoded key ID as "kid"
  value. Keys with output prefix type "RAW" will not have a "kid" value set.

  Currently, public keys for algorithms ES256, ES384, ES512, RS256, RS384,
  RS512, PS256, PS384 and PS512 supported.

  Args:
    keyset_handle: A Tink KeysetHandle that contains JWT Keys.

  Returns:
    A JWK set, which is a JSON encoded string.

  Raises:
    TinkError if the keys are not of the expected type, or if they have a
    ouput prefix type that is not supported.
  """
  serialization = tink.proto_keyset_format.serialize_without_secret(
      keyset_handle
  )
  keyset = tink_pb2.Keyset.FromString(serialization)
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
    elif key.key_data.type_url == _JWT_RSA_SSA_PKCS1_PUBLIC_KEY_TYPE:
      keys.append(_convert_jwt_rsa_ssa_pkcs1_key(key))
    elif key.key_data.type_url == _JWT_RSA_SSA_PSS_PUBLIC_KEY_TYPE:
      keys.append(_convert_jwt_rsa_ssa_pss_key(key))
    else:
      raise tink.TinkError('unknown key type: %s' % key.key_data.type_url)
  return json.dumps({'keys': keys}, separators=(',', ':'))


# Deprecated. Use from_public_keyset_handle instead.
def from_keyset_handle(keyset_handle: tink.KeysetHandle,
                       key_access: Optional[tink.KeyAccess] = None) -> str:
  _ = key_access
  return from_public_keyset_handle(keyset_handle)


def _convert_jwt_ecdsa_key(
    key: tink_pb2.Keyset.Key) -> Dict[str, Union[str, List[str]]]:
  """Converts a JwtEcdsaPublicKey into a JWK."""
  ecdsa_public_key = jwt_ecdsa_pb2.JwtEcdsaPublicKey.FromString(
      key.key_data.value)
  if ecdsa_public_key.algorithm not in _ECDSA_PARAMS:
    raise tink.TinkError('unknown ecdsa algorithm')
  alg, crv = _ECDSA_PARAMS[ecdsa_public_key.algorithm]
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


def _convert_jwt_rsa_ssa_pkcs1_key(
    key: tink_pb2.Keyset.Key) -> Dict[str, Union[str, List[str]]]:
  """Converts a JwtRsaSsaPkcs1PublicKey into a JWK."""
  public_key = jwt_rsa_ssa_pkcs1_pb2.JwtRsaSsaPkcs1PublicKey.FromString(
      key.key_data.value)
  if public_key.algorithm not in _RSA_SSA_PKCS1_PARAMS:
    raise tink.TinkError('unknown RSA SSA PKCS1 algorithm')
  alg = _RSA_SSA_PKCS1_PARAMS[public_key.algorithm]
  output = {
      'kty': 'RSA',
      'n': _base64_encode(public_key.n),
      'e': _base64_encode(public_key.e),
      'use': 'sig',
      'alg': alg,
      'key_ops': ['verify'],
  }
  kid = _jwt_format.get_kid(key.key_id, key.output_prefix_type)
  if kid:
    output['kid'] = kid
  elif public_key.HasField('custom_kid'):
    output['kid'] = public_key.custom_kid.value
  return output


def _convert_jwt_rsa_ssa_pss_key(
    key: tink_pb2.Keyset.Key) -> Dict[str, Union[str, List[str]]]:
  """Converts a JwtRsaSsaPssPublicKey into a JWK."""
  public_key = jwt_rsa_ssa_pss_pb2.JwtRsaSsaPssPublicKey.FromString(
      key.key_data.value)
  if public_key.algorithm not in _RSA_SSA_PSS_PARAMS:
    raise tink.TinkError('unknown RSA SSA PSS algorithm')
  alg = _RSA_SSA_PSS_PARAMS[public_key.algorithm]
  output = {
      'kty': 'RSA',
      'n': _base64_encode(public_key.n),
      'e': _base64_encode(public_key.e),
      'use': 'sig',
      'alg': alg,
      'key_ops': ['verify'],
  }
  kid = _jwt_format.get_kid(key.key_id, key.output_prefix_type)
  if kid:
    output['kid'] = kid
  elif public_key.HasField('custom_kid'):
    output['kid'] = public_key.custom_kid.value
  return output


def _generate_unused_key_id(keyset: tink_pb2.Keyset) -> int:
  while True:
    key_id = random.randint(1, 2147483647)
    if key_id not in {key.key_id for key in keyset.key}:
      return key_id


def to_public_keyset_handle(jwk_set: str) -> tink.KeysetHandle:
  """Converts a Json Web Key (JWK) set into a Tink KeysetHandle with JWT keys.

  JWK is defined in https://www.rfc-editor.org/rfc/rfc7517.txt.

  All keys are converted into Tink keys with output prefix type "RAW".

  Currently, public keys for algorithms ES256, ES384, ES512, RS256, RS384,
  RS512, PS256, PS384 and PS512 supported.

  Args:
    jwk_set: A JWK set, which is a JSON encoded string.

  Returns:
    A tink.KeysetHandle.

  Raises:
    TinkError if the key cannot be converted.
  """
  try:
    keys_dict = json.loads(jwk_set)
  except json.decoder.JSONDecodeError as e:
    raise tink.TinkError('error parsing JWK set: %s' % e.msg)
  if 'keys' not in keys_dict:
    raise tink.TinkError('invalid JWK set: keys not found')
  proto_keyset = tink_pb2.Keyset()
  for key in keys_dict['keys']:
    if 'alg' not in key:
      raise tink.TinkError('invalid JWK: alg not found')
    alg = key['alg']
    if alg.startswith('ES'):
      proto_key = _convert_to_ecdsa_key(key)
    elif alg.startswith('RS'):
      proto_key = _convert_to_rsa_ssa_pkcs1_key(key)
    elif alg.startswith('PS'):
      proto_key = _convert_to_rsa_ssa_pss_key(key)
    else:
      raise tink.TinkError('unknown alg')
    new_id = _generate_unused_key_id(proto_keyset)
    proto_key.key_id = new_id
    proto_keyset.key.append(proto_key)
    # JWK sets do not really have a primary key (see RFC 7517, Section 5.1).
    # To verify signature, it also does not matter which key is primary. We
    # simply set it to the last key.
    proto_keyset.primary_key_id = new_id
  return tink.proto_keyset_format.parse_without_secret(
      proto_keyset.SerializeToString()
  )


# Deprecated. Use to_public_keyset_handle instead.
def to_keyset_handle(
    jwk_set: str,
    key_access: Optional[tink.KeyAccess] = None) -> tink.KeysetHandle:
  _ = key_access
  return to_public_keyset_handle(jwk_set)


def _validate_use_and_key_ops(key: Dict[str, Union[str, List[str]]]):
  """Checks that 'key_ops' and 'use' have the right values if present."""
  if 'key_ops' in key:
    key_ops = key['key_ops']
    if len(key_ops) != 1 or key_ops[0] != 'verify':
      raise tink.TinkError('invalid key_ops')
  if 'use' in key and key['use'] != 'sig':
    raise tink.TinkError('invalid use')


def _convert_to_ecdsa_key(
    key: Dict[str, Union[str, List[str]]]) -> tink_pb2.Keyset.Key:
  """Converts a EC Json Web Key (JWK) into a tink_pb2.Keyset.Key."""
  ecdsa_public_key = jwt_ecdsa_pb2.JwtEcdsaPublicKey()
  algorithm = _ECDSA_NAME_TO_ALGORITHM.get(cast(str, key['alg']), None)
  if not algorithm:
    raise tink.TinkError('unknown ECDSA algorithm')
  if key.get('kty', None) != 'EC':
    raise tink.TinkError('invalid kty')
  _, crv = _ECDSA_PARAMS[algorithm]
  if key.get('crv', None) != crv:
    raise tink.TinkError('invalid crv')
  _validate_use_and_key_ops(key)
  if 'd' in key:
    raise tink.TinkError('cannot convert private ECDSA key')
  ecdsa_public_key.algorithm = algorithm
  ecdsa_public_key.x = _base64_decode(cast(str, key['x']))
  ecdsa_public_key.y = _base64_decode(cast(str, key['y']))
  if 'kid' in key:
    ecdsa_public_key.custom_kid.value = key['kid']
  proto_key = tink_pb2.Keyset.Key()
  proto_key.key_data.type_url = _JWT_ECDSA_PUBLIC_KEY_TYPE
  proto_key.key_data.value = ecdsa_public_key.SerializeToString()
  proto_key.key_data.key_material_type = tink_pb2.KeyData.ASYMMETRIC_PUBLIC
  proto_key.output_prefix_type = tink_pb2.RAW
  proto_key.status = tink_pb2.ENABLED
  return proto_key


def _convert_to_rsa_ssa_pkcs1_key(
    key: Dict[str, Union[str, List[str]]]) -> tink_pb2.Keyset.Key:
  """Converts a JWK into a JwtEcdsaPublicKey."""
  public_key = jwt_rsa_ssa_pkcs1_pb2.JwtRsaSsaPkcs1PublicKey()
  algorithm = _RSA_SSA_PKCS1_NAME_TO_ALGORITHM.get(cast(str, key['alg']), None)
  if not algorithm:
    raise tink.TinkError('unknown RSA SSA PKCS1 algorithm')
  if key.get('kty', None) != 'RSA':
    raise tink.TinkError('invalid kty')
  _validate_use_and_key_ops(key)
  if ('p' in key or 'q' in key or 'dp' in key or 'dq' in key or 'd' in key or
      'qi' in key):
    raise tink.TinkError('importing RSA private keys is not implemented')
  public_key.algorithm = algorithm
  public_key.n = _base64_decode(cast(str, key['n']))
  public_key.e = _base64_decode(cast(str, key['e']))
  if 'kid' in key:
    public_key.custom_kid.value = key['kid']
  proto_key = tink_pb2.Keyset.Key()
  proto_key.key_data.type_url = _JWT_RSA_SSA_PKCS1_PUBLIC_KEY_TYPE
  proto_key.key_data.value = public_key.SerializeToString()
  proto_key.key_data.key_material_type = tink_pb2.KeyData.ASYMMETRIC_PUBLIC
  proto_key.output_prefix_type = tink_pb2.RAW
  proto_key.status = tink_pb2.ENABLED
  return proto_key


def _convert_to_rsa_ssa_pss_key(
    key: Dict[str, Union[str, List[str]]]) -> tink_pb2.Keyset.Key:
  """Converts a JWK into a JwtEcdsaPublicKey."""
  public_key = jwt_rsa_ssa_pss_pb2.JwtRsaSsaPssPublicKey()
  algorithm = _RSA_SSA_PSS_NAME_TO_ALGORITHM.get(cast(str, key['alg']), None)
  if not algorithm:
    raise tink.TinkError('unknown RSA SSA PSS algorithm')
  if key.get('kty', None) != 'RSA':
    raise tink.TinkError('invalid kty')
  _validate_use_and_key_ops(key)
  if ('p' in key or 'q' in key or 'dp' in key or 'dq' in key or 'd' in key or
      'qi' in key):
    raise tink.TinkError('importing RSA private keys is not implemented')
  public_key.algorithm = algorithm
  public_key.n = _base64_decode(cast(str, key['n']))
  public_key.e = _base64_decode(cast(str, key['e']))
  if 'kid' in key:
    public_key.custom_kid.value = cast(str, key['kid'])
  proto_key = tink_pb2.Keyset.Key()
  proto_key.key_data.type_url = _JWT_RSA_SSA_PSS_PUBLIC_KEY_TYPE
  proto_key.key_data.value = public_key.SerializeToString()
  proto_key.key_data.key_material_type = tink_pb2.KeyData.ASYMMETRIC_PUBLIC
  proto_key.output_prefix_type = tink_pb2.RAW
  proto_key.status = tink_pb2.ENABLED
  return proto_key
