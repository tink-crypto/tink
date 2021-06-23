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

from typing import Text, Type, Callable

from tink.proto import jwt_ecdsa_pb2
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

_ECDSA_ALGORITHM_TEXTS = {
    jwt_ecdsa_pb2.ES256: 'ES256',
    jwt_ecdsa_pb2.ES384: 'ES384',
    jwt_ecdsa_pb2.ES512: 'ES512'
}


class _JwtPublicKeySign(_jwt_public_key_sign.JwtPublicKeySign):
  """Implementation of JwtPublicKeySign using a PublicKeySign."""

  def __init__(self, cc_primitive: tink_bindings.PublicKeySign,
               algorithm: Text):
    self._public_key_sign = cc_primitive
    self._algorithm = algorithm

  @core.use_tink_errors
  def _sign(self, data: bytes) -> bytes:
    return self._public_key_sign.sign(data)

  # TODO(juerg): Add kid, as in Java and C++.
  def sign_and_encode(self, token: _raw_jwt.RawJwt) -> Text:
    """Computes a signature and encodes the token."""
    type_header = token.type_header() if token.has_type_header() else None
    unsigned = _jwt_format.create_unsigned_compact(self._algorithm,
                                                   type_header,
                                                   token.json_payload())
    return _jwt_format.create_signed_compact(unsigned, self._sign(unsigned))


class _JwtPublicKeyVerify(_jwt_public_key_verify.JwtPublicKeyVerify):
  """Implementation of JwtPublicKeyVerify using a PublicKeyVerify."""

  def __init__(self, cc_primitive: tink_bindings.PublicKeyVerify,
               algorithm: Text):
    self._public_key_verify = cc_primitive
    self._algorithm = algorithm

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
    core.PrivateKeyManager[_jwt_public_key_sign.JwtPublicKeySign]):
  """Converts a C++ sign key manager into a JwtPublicKeySignKeyManager."""

  def __init__(
      self,
      cc_key_manager: tink_bindings.PublicKeySignKeyManager,
      key_data_to_algorithm: Callable[[tink_pb2.KeyData], Text]):
    self._cc_key_manager = cc_key_manager
    self._key_data_to_algorithm = key_data_to_algorithm

  def primitive_class(self) -> Type[_jwt_public_key_sign.JwtPublicKeySign]:
    return _jwt_public_key_sign.JwtPublicKeySign

  @core.use_tink_errors
  def primitive(
      self,
      key_data: tink_pb2.KeyData) -> _jwt_public_key_sign.JwtPublicKeySign:
    sign = self._cc_key_manager.primitive(key_data.SerializeToString())
    algorithm = self._key_data_to_algorithm(key_data)
    return _JwtPublicKeySign(sign, algorithm)

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

  def __init__(
      self,
      cc_key_manager: tink_bindings.PublicKeyVerifyKeyManager,
      key_data_to_algorithm: Callable[[tink_pb2.KeyData], Text]):
    self._cc_key_manager = cc_key_manager
    self._key_data_to_algorithm = key_data_to_algorithm

  def primitive_class(self) -> Type[_jwt_public_key_verify.JwtPublicKeyVerify]:
    return _jwt_public_key_verify.JwtPublicKeyVerify

  @core.use_tink_errors
  def primitive(
      self,
      key_data: tink_pb2.KeyData) -> _jwt_public_key_verify.JwtPublicKeyVerify:
    verify = self._cc_key_manager.primitive(key_data.SerializeToString())
    algorithm = self._key_data_to_algorithm(key_data)
    return _JwtPublicKeyVerify(verify, algorithm)

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


def _ecdsa_algorithm_from_private_key_data(key_data: tink_pb2.KeyData) -> Text:
  if key_data.type_url != _JWT_ECDSA_PRIVATE_KEY_TYPE:
    raise _jwt_error.JwtInvalidError('Invalid key data key type')
  key = jwt_ecdsa_pb2.JwtEcdsaPrivateKey.FromString(key_data.value)
  return _ecdsa_algorithm_text(key.public_key.algorithm)


def _ecdsa_algorithm_from_public_key_data(key_data: tink_pb2.KeyData) -> Text:
  if key_data.type_url != _JWT_ECDSA_PUBLIC_KEY_TYPE:
    raise _jwt_error.JwtInvalidError('Invalid key data key type')
  key = jwt_ecdsa_pb2.JwtEcdsaPublicKey.FromString(key_data.value)
  return _ecdsa_algorithm_text(key.algorithm)


def register():
  """Registers all JWT signature primitives."""
  tink_bindings.register_jwt()

  private_key_manager = _JwtPublicKeySignKeyManagerCcToPyWrapper(
      tink_bindings.PublicKeySignKeyManager.from_cc_registry(
          _JWT_ECDSA_PRIVATE_KEY_TYPE), _ecdsa_algorithm_from_private_key_data)
  core.Registry.register_key_manager(private_key_manager, new_key_allowed=True)

  public_key_manager = _JwtPublicKeyVerifyKeyManagerCcToPyWrapper(
      tink_bindings.PublicKeyVerifyKeyManager.from_cc_registry(
          _JWT_ECDSA_PUBLIC_KEY_TYPE), _ecdsa_algorithm_from_public_key_data)
  core.Registry.register_key_manager(public_key_manager, new_key_allowed=True)
