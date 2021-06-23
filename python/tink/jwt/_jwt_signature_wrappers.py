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
"""Python primitive set wrapper for the JwtMac primitive."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from typing import Optional, Text, Type

from tink.proto import tink_pb2
from tink import core
from tink.jwt import _jwt_error
from tink.jwt import _jwt_public_key_sign
from tink.jwt import _jwt_public_key_verify
from tink.jwt import _jwt_validator
from tink.jwt import _raw_jwt
from tink.jwt import _verified_jwt


class _WrappedJwtPublicKeySign(_jwt_public_key_sign.JwtPublicKeySign):
  """A wrapped JwtPublicKeySign."""

  def __init__(self, pset: core.PrimitiveSet):
    self._primitive_set = pset

  def sign_and_encode(self, raw_jwt: _raw_jwt.RawJwt) -> Text:
    primary = self._primitive_set.primary()
    if primary.output_prefix_type != tink_pb2.RAW:
      raise core.TinkError('unexpected output prefix type')
    return primary.primitive.sign_and_encode(raw_jwt)


class _WrappedJwtPublicKeyVerify(_jwt_public_key_verify.JwtPublicKeyVerify):
  """A wrapped JwtPublicKeyVerify."""

  def __init__(self, pset: core.PrimitiveSet):
    self._primitive_set = pset

  def verify_and_decode(
      self, compact: Text,
      validator: _jwt_validator.JwtValidator) -> _verified_jwt.VerifiedJwt:
    interesting_error = None
    for entry in self._primitive_set.raw_primitives():
      try:
        return entry.primitive.verify_and_decode(compact, validator)
      except core.TinkError as e:
        if isinstance(e, _jwt_error.JwtInvalidError):
          interesting_error = e
        pass
    if interesting_error:
      raise interesting_error
    raise core.TinkError('invalid signature')


class _JwtPublicKeySignWrapper(
    core.PrimitiveWrapper[_jwt_public_key_sign.JwtPublicKeySign,
                          _jwt_public_key_sign.JwtPublicKeySign]):
  """A wrapper for JwtPublicKeySign."""

  def wrap(
      self, pset: core.PrimitiveSet
  ) -> Optional[_jwt_public_key_sign.JwtPublicKeySign]:
    return _WrappedJwtPublicKeySign(pset)

  def primitive_class(self) -> Type[_jwt_public_key_sign.JwtPublicKeySign]:
    return _jwt_public_key_sign.JwtPublicKeySign

  def input_primitive_class(
      self) -> Type[_jwt_public_key_sign.JwtPublicKeySign]:
    return _jwt_public_key_sign.JwtPublicKeySign


class _JwtPublicKeyVerifyWrapper(
    core.PrimitiveWrapper[_jwt_public_key_verify.JwtPublicKeyVerify,
                          _jwt_public_key_verify.JwtPublicKeyVerify]):
  """A wrapper for JwtPublicKeyVerify."""

  def wrap(
      self, pset: core.PrimitiveSet
  ) -> Optional[_jwt_public_key_verify.JwtPublicKeyVerify]:
    return _WrappedJwtPublicKeyVerify(pset)

  def primitive_class(self) -> Type[_jwt_public_key_verify.JwtPublicKeyVerify]:
    return _jwt_public_key_verify.JwtPublicKeyVerify

  def input_primitive_class(
      self) -> Type[_jwt_public_key_verify.JwtPublicKeyVerify]:
    return _jwt_public_key_verify.JwtPublicKeyVerify


def register():
  core.Registry.register_primitive_wrapper(_JwtPublicKeySignWrapper())
  core.Registry.register_primitive_wrapper(_JwtPublicKeyVerifyWrapper())
