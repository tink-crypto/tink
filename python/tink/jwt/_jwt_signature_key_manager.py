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
"""JWT Signature key managers."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from typing import Any, Optional, Text, Type, Tuple, Callable

from tink.proto import jwt_ecdsa_pb2
from tink.proto import jwt_rsa_ssa_pkcs1_pb2
from tink.proto import jwt_rsa_ssa_pss_pb2
from tink.proto import tink_pb2
from tink import core
from tink.cc.pybind import tink_bindings
from tink.jwt import _jwt_error
from tink.jwt import _jwt_format
from tink.jwt import _jwt_public_key_sign
from tink.jwt import _jwt_public_key_verify
from tink.jwt import _jwt_validator
from tink.jwt import _raw_jwt
from tink.jwt import _verified_jwt

_JWT_ECDSA_PRIVATE_KEY_TYPE = 'type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey'
_JWT_ECDSA_PUBLIC_KEY_TYPE = 'type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey'

_JWT_RSA_SSA_PKCS1_PRIVATE_KEY_TYPE = 'type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PrivateKey'
_JWT_RSA_SSA_PKCS1_PUBLIC_KEY_TYPE = 'type.googleapis.com/google.crypto.tink.JwtRsaSsaPkcs1PublicKey'

_JWT_RSA_SSA_PSS_PRIVATE_KEY_TYPE = 'type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPrivateKey'
_JWT_RSA_SSA_PSS_PUBLIC_KEY_TYPE = 'type.googleapis.com/google.crypto.tink.JwtRsaSsaPssPublicKey'

_ECDSA_ALGORITHM_TEXTS = {
    jwt_ecdsa_pb2.ES256: 'ES256',
    jwt_ecdsa_pb2.ES384: 'ES384',
    jwt_ecdsa_pb2.ES512: 'ES512'
}

_RSA_SSA_PKCS1_ALGORITHM_TEXTS = {
    jwt_rsa_ssa_pkcs1_pb2.RS256: 'RS256',
    jwt_rsa_ssa_pkcs1_pb2.RS384: 'RS384',
    jwt_rsa_ssa_pkcs1_pb2.RS512: 'RS512'
}

_RSA_SSA_PSS_ALGORITHM_TEXTS = {
    jwt_rsa_ssa_pss_pb2.PS256: 'PS256',
    jwt_rsa_ssa_pss_pb2.PS384: 'PS384',
    jwt_rsa_ssa_pss_pb2.PS512: 'PS512'
}


class _JwtPublicKeySign(_jwt_public_key_sign.JwtPublicKeySignInternal):
  """Implementation of JwtPublicKeySignInternal using a PublicKeySign."""

  def __init__(self, cc_primitive: tink_bindings.PublicKeySign, algorithm: Text,
               custom_kid: Text):
    self._public_key_sign = cc_primitive
    self._algorithm = algorithm
    self._custom_kid = custom_kid

  @core.use_tink_errors
  def _sign(self, data: bytes) -> bytes:
    return self._public_key_sign.sign(data)

  def sign_and_encode_with_kid(self, raw_jwt: _raw_jwt.RawJwt,
                               kid: Optional[Text]) -> Text:
    """Computes a signature and encodes the token.

    Args:
      raw_jwt: The RawJwt token to be MACed and encoded.
      kid: Optional "kid" header value. It is set by the wrapper for keys with
        output prefix TINK, and it is None for output prefix RAW.

    Returns:
      The MACed token encoded in the JWS compact serialization format.
    Raises:
      tink.TinkError if the operation fails.
    """
    type_header = raw_jwt.type_header() if raw_jwt.has_type_header() else None
    if self._custom_kid is not None:
      if kid is not None:
        raise _jwt_error.JwtInvalidError(
            'custom_kid must not be set for keys with output prefix type TINK')
      kid = self._custom_kid
    unsigned = _jwt_format.create_unsigned_compact(self._algorithm, type_header,
                                                   kid, raw_jwt.json_payload())
    return _jwt_format.create_signed_compact(unsigned, self._sign(unsigned))


class _JwtPublicKeyVerify(_jwt_public_key_verify.JwtPublicKeyVerify):
  """Implementation of JwtPublicKeyVerify using a PublicKeyVerify."""

  def __init__(self, cc_primitive: tink_bindings.PublicKeyVerify,
               algorithm: Text, custom_kid: Optional[Text]):
    self._public_key_verify = cc_primitive
    self._algorithm = algorithm
    self._custom_kid = custom_kid

  @core.use_tink_errors
  def _verify(self, signature: bytes, data: bytes) -> None:
    self._public_key_verify.verify(signature, data)

  def verify_and_decode(
      self, compact: Text,
      validator: _jwt_validator.JwtValidator) -> _verified_jwt.VerifiedJwt:
    """Verifies, validates and decodes a signed compact JWT token."""
    parts = _jwt_format.split_signed_compact(compact)
    unsigned_compact, json_header, json_payload, signature = parts
    self._verify(signature, unsigned_compact)
    header = _jwt_format.json_loads(json_header)
    _jwt_format.validate_header(header, self._algorithm)
    raw_jwt = _raw_jwt.RawJwt.from_json(
        _jwt_format.get_type_header(header), json_payload)
    _jwt_validator.validate(validator, raw_jwt)
    return _verified_jwt.VerifiedJwt._create(raw_jwt)  # pylint: disable=protected-access


class _JwtPublicKeySignKeyManagerCcToPyWrapper(
    core.PrivateKeyManager[_jwt_public_key_sign.JwtPublicKeySignInternal]):
  """Converts a C++ sign key manager into a JwtPublicKeySignKeyManager."""

  def __init__(self, cc_key_manager: tink_bindings.PublicKeySignKeyManager,
               key_data_to_alg_kid: Callable[[tink_pb2.KeyData],
                                             Tuple[Text, Optional[Text]]]):
    self._cc_key_manager = cc_key_manager
    self._key_data_to_alg_kid = key_data_to_alg_kid

  def primitive_class(
      self) -> Type[_jwt_public_key_sign.JwtPublicKeySignInternal]:
    return _jwt_public_key_sign.JwtPublicKeySignInternal

  @core.use_tink_errors
  def primitive(
      self, key_data: tink_pb2.KeyData
  ) -> _jwt_public_key_sign.JwtPublicKeySignInternal:
    sign = self._cc_key_manager.primitive(key_data.SerializeToString())
    algorithm, custom_kid = self._key_data_to_alg_kid(key_data)
    return _JwtPublicKeySign(sign, algorithm, custom_kid)

  def key_type(self) -> Text:
    return self._cc_key_manager.key_type()

  @core.use_tink_errors
  def new_key_data(self,
                   key_template: tink_pb2.KeyTemplate) -> tink_pb2.KeyData:
    return tink_pb2.KeyData.FromString(
        self._cc_key_manager.new_key_data(key_template.SerializeToString()))

  @core.use_tink_errors
  def public_key_data(self, key_data: tink_pb2.KeyData) -> tink_pb2.KeyData:
    return tink_pb2.KeyData.FromString(
        self._cc_key_manager.public_key_data(key_data.SerializeToString()))


class _JwtPublicKeyVerifyKeyManagerCcToPyWrapper(
    core.KeyManager[_jwt_public_key_verify.JwtPublicKeyVerify]):
  """Converts a C++ verify key manager into a JwtPublicKeyVerifyKeyManager."""

  def __init__(self, cc_key_manager: tink_bindings.PublicKeyVerifyKeyManager,
               key_data_to_alg_kid: Callable[[tink_pb2.KeyData],
                                             Tuple[Text, Optional[Text]]]):
    self._cc_key_manager = cc_key_manager
    self._key_data_to_alg_kid = key_data_to_alg_kid

  def primitive_class(self) -> Type[_jwt_public_key_verify.JwtPublicKeyVerify]:
    return _jwt_public_key_verify.JwtPublicKeyVerify

  @core.use_tink_errors
  def primitive(
      self,
      key_data: tink_pb2.KeyData) -> _jwt_public_key_verify.JwtPublicKeyVerify:
    verify = self._cc_key_manager.primitive(key_data.SerializeToString())
    algorithm, custom_kid = self._key_data_to_alg_kid(key_data)
    return _JwtPublicKeyVerify(verify, algorithm, custom_kid)

  def key_type(self) -> Text:
    return self._cc_key_manager.key_type()

  @core.use_tink_errors
  def new_key_data(self,
                   key_template: tink_pb2.KeyTemplate) -> tink_pb2.KeyData:
    return tink_pb2.KeyData.FromString(
        self._cc_key_manager.new_key_data(key_template.SerializeToString()))


def _ecdsa_algorithm_text(algorithm: jwt_ecdsa_pb2.JwtEcdsaAlgorithm) -> Text:
  if algorithm not in _ECDSA_ALGORITHM_TEXTS:
    raise _jwt_error.JwtInvalidError('Invalid algorithm')
  return _ECDSA_ALGORITHM_TEXTS[algorithm]


def _get_custom_kid(public_key_proto: Any) -> Optional[Text]:
  if public_key_proto.HasField('custom_kid'):
    return public_key_proto.custom_kid.value
  else:
    return None


def _ecdsa_alg_kid_from_private_key_data(
    key_data: tink_pb2.KeyData) -> Tuple[Text, Optional[Text]]:
  if key_data.type_url != _JWT_ECDSA_PRIVATE_KEY_TYPE:
    raise _jwt_error.JwtInvalidError('Invalid key data key type')
  key = jwt_ecdsa_pb2.JwtEcdsaPrivateKey.FromString(key_data.value)
  return (_ecdsa_algorithm_text(key.public_key.algorithm),
          _get_custom_kid(key.public_key))


def _ecdsa_alg_kid_from_public_key_data(
    key_data: tink_pb2.KeyData) -> Tuple[Text, Optional[Text]]:
  if key_data.type_url != _JWT_ECDSA_PUBLIC_KEY_TYPE:
    raise _jwt_error.JwtInvalidError('Invalid key data key type')
  key = jwt_ecdsa_pb2.JwtEcdsaPublicKey.FromString(key_data.value)
  return (_ecdsa_algorithm_text(key.algorithm), _get_custom_kid(key))


def _rsa_ssa_pkcs1_algorithm_text(
    algorithm: jwt_rsa_ssa_pkcs1_pb2.JwtRsaSsaPkcs1Algorithm) -> Text:
  if algorithm not in _RSA_SSA_PKCS1_ALGORITHM_TEXTS:
    raise _jwt_error.JwtInvalidError('Invalid algorithm')
  return _RSA_SSA_PKCS1_ALGORITHM_TEXTS[algorithm]


def _rsa_ssa_pkcs1_alg_kid_from_private_key_data(
    key_data: tink_pb2.KeyData) -> Tuple[Text, Optional[Text]]:
  if key_data.type_url != _JWT_RSA_SSA_PKCS1_PRIVATE_KEY_TYPE:
    raise _jwt_error.JwtInvalidError('Invalid key data key type')
  key = jwt_rsa_ssa_pkcs1_pb2.JwtRsaSsaPkcs1PrivateKey.FromString(
      key_data.value)
  return (_rsa_ssa_pkcs1_algorithm_text(key.public_key.algorithm),
          _get_custom_kid(key.public_key))


def _rsa_ssa_pkcs1_alg_kid_from_public_key_data(
    key_data: tink_pb2.KeyData) -> Tuple[Text, Optional[Text]]:
  if key_data.type_url != _JWT_RSA_SSA_PKCS1_PUBLIC_KEY_TYPE:
    raise _jwt_error.JwtInvalidError('Invalid key data key type')
  key = jwt_rsa_ssa_pkcs1_pb2.JwtRsaSsaPkcs1PublicKey.FromString(key_data.value)
  return (_rsa_ssa_pkcs1_algorithm_text(key.algorithm), _get_custom_kid(key))


def _rsa_ssa_pss_algorithm_text(
    algorithm: jwt_rsa_ssa_pss_pb2.JwtRsaSsaPssAlgorithm) -> Text:
  if algorithm not in _RSA_SSA_PSS_ALGORITHM_TEXTS:
    raise _jwt_error.JwtInvalidError('Invalid algorithm')
  return _RSA_SSA_PSS_ALGORITHM_TEXTS[algorithm]


def _rsa_ssa_pss_alg_kid_from_private_key_data(
    key_data: tink_pb2.KeyData) -> Tuple[Text, Optional[Text]]:
  if key_data.type_url != _JWT_RSA_SSA_PSS_PRIVATE_KEY_TYPE:
    raise _jwt_error.JwtInvalidError('Invalid key data key type')
  key = jwt_rsa_ssa_pss_pb2.JwtRsaSsaPssPrivateKey.FromString(key_data.value)
  return (_rsa_ssa_pss_algorithm_text(key.public_key.algorithm),
          _get_custom_kid(key.public_key))


def _rsa_ssa_pss_alg_kid_from_public_key_data(
    key_data: tink_pb2.KeyData) -> Tuple[Text, Optional[Text]]:
  if key_data.type_url != _JWT_RSA_SSA_PSS_PUBLIC_KEY_TYPE:
    raise _jwt_error.JwtInvalidError('Invalid key data key type')
  key = jwt_rsa_ssa_pss_pb2.JwtRsaSsaPssPublicKey.FromString(key_data.value)
  return (_rsa_ssa_pss_algorithm_text(key.algorithm), _get_custom_kid(key))


def register():
  """Registers all JWT signature primitives."""
  tink_bindings.register_jwt()

  private_key_manager = _JwtPublicKeySignKeyManagerCcToPyWrapper(
      tink_bindings.PublicKeySignKeyManager.from_cc_registry(
          _JWT_ECDSA_PRIVATE_KEY_TYPE), _ecdsa_alg_kid_from_private_key_data)
  core.Registry.register_key_manager(private_key_manager, new_key_allowed=True)

  public_key_manager = _JwtPublicKeyVerifyKeyManagerCcToPyWrapper(
      tink_bindings.PublicKeyVerifyKeyManager.from_cc_registry(
          _JWT_ECDSA_PUBLIC_KEY_TYPE), _ecdsa_alg_kid_from_public_key_data)
  core.Registry.register_key_manager(public_key_manager, new_key_allowed=True)

  private_key_manager = _JwtPublicKeySignKeyManagerCcToPyWrapper(
      tink_bindings.PublicKeySignKeyManager.from_cc_registry(
          _JWT_RSA_SSA_PKCS1_PRIVATE_KEY_TYPE),
      _rsa_ssa_pkcs1_alg_kid_from_private_key_data)
  core.Registry.register_key_manager(private_key_manager, new_key_allowed=True)

  public_key_manager = _JwtPublicKeyVerifyKeyManagerCcToPyWrapper(
      tink_bindings.PublicKeyVerifyKeyManager.from_cc_registry(
          _JWT_RSA_SSA_PKCS1_PUBLIC_KEY_TYPE),
      _rsa_ssa_pkcs1_alg_kid_from_public_key_data)
  core.Registry.register_key_manager(public_key_manager, new_key_allowed=True)

  private_key_manager = _JwtPublicKeySignKeyManagerCcToPyWrapper(
      tink_bindings.PublicKeySignKeyManager.from_cc_registry(
          _JWT_RSA_SSA_PSS_PRIVATE_KEY_TYPE),
      _rsa_ssa_pss_alg_kid_from_private_key_data)
  core.Registry.register_key_manager(private_key_manager, new_key_allowed=True)

  public_key_manager = _JwtPublicKeyVerifyKeyManagerCcToPyWrapper(
      tink_bindings.PublicKeyVerifyKeyManager.from_cc_registry(
          _JWT_RSA_SSA_PSS_PUBLIC_KEY_TYPE),
      _rsa_ssa_pss_alg_kid_from_public_key_data)
  core.Registry.register_key_manager(public_key_manager, new_key_allowed=True)
