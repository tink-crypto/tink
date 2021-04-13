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
from tink.jwt import _jwt_mac
from tink.jwt import _jwt_validator
from tink.jwt import _raw_jwt
from tink.jwt import _verified_jwt


class _WrappedJwtMac(_jwt_mac.JwtMac):
  """A wrapped JwtMac."""

  def __init__(self, pset: core.PrimitiveSet):
    self._primitive_set = pset

  def compute_mac_and_encode(self, raw_jwt: _raw_jwt.RawJwt) -> Text:
    """Computes a MAC and encodes the token.

    Args:
      raw_jwt: The RawJwt token to be MACed and encoded.

    Returns:
      The MACed token encoded in the JWS compact serialization format.
    Raises:
      tink.TinkError if the operation fails.
    """
    primary = self._primitive_set.primary()
    if primary.output_prefix_type != tink_pb2.RAW:
      raise core.TinkError('unexpected output prefix type')
    return primary.primitive.compute_mac_and_encode(raw_jwt)

  def verify_mac_and_decode(
      self, compact: Text,
      validator: _jwt_validator.JwtValidator) -> _verified_jwt.VerifiedJwt:
    """Verifies, validates and decodes a MACed compact JWT token.

    Args:
      compact: A MACed token encoded in the JWS compact serialization format.
      validator: A JwtValidator that validates the token.

    Returns:
      A VerifiedJwt.
    Raises:
      tink.TinkError if the operation fails.
    """
    interesting_error = None
    for entry in self._primitive_set.raw_primitives():
      try:
        return entry.primitive.verify_mac_and_decode(compact, validator)
      except core.TinkError as e:
        if isinstance(e, _jwt_error.JwtInvalidError):
          interesting_error = e
        pass
    if interesting_error:
      raise interesting_error
    raise core.TinkError('invalid MAC')


class _Wrapper(core.PrimitiveWrapper[_jwt_mac.JwtMac, _jwt_mac.JwtMac]):
  """A wrapper for JwtMac."""

  def wrap(self, pset: core.PrimitiveSet) -> Optional[_jwt_mac.JwtMac]:

    return _WrappedJwtMac(pset)

  def primitive_class(self) -> Type[_jwt_mac.JwtMac]:
    return _jwt_mac.JwtMac

  def input_primitive_class(self) -> Type[_jwt_mac.JwtMac]:
    return _jwt_mac.JwtMac


def register():
  core.Registry.register_primitive_wrapper(_Wrapper())
