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
"""Interface for JwtPublicKeySign."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import abc
from typing import Optional, Text

import six

from tink.jwt import _raw_jwt


@six.add_metaclass(abc.ABCMeta)
class JwtPublicKeySign(object):
  """Interface for creating a signed JWT.

  Sees RFC 7519 and RFC 7515. Security guarantees: similar to PublicKeySign.
  """

  @abc.abstractmethod
  def sign_and_encode(self, raw_jwt: _raw_jwt.RawJwt) -> Text:
    """Computes a signature and encodes the token.

    Args:
      raw_jwt: The RawJwt token to be signed and encoded.

    Returns:
      The signed token encoded in the JWS compact serialization format.
    Raises:
      tink.TinkError if the operation fails.
    """
    raise NotImplementedError()


@six.add_metaclass(abc.ABCMeta)
class JwtPublicKeySignInternal(object):
  """Internal interface for creating a signed JWT.

  "kid" is an optional value that is set by the wrapper for keys with output
  prefix TINK, and it is set to None for output prefix RAW.
  """

  @abc.abstractmethod
  def sign_and_encode_with_kid(self, token: _raw_jwt.RawJwt,
                               kid: Optional[Text]) -> Text:
    raise NotImplementedError()
