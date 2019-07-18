# Copyright 2019 Google LLC
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

"""Public Key Sign wrapper."""

from __future__ import absolute_import
from __future__ import division
from __future__ import google_type_annotations
from __future__ import print_function

from typing import Type

from tink.proto import tink_pb2
from tink.python.core import crypto_format
from tink.python.core import primitive_set
from tink.python.core import primitive_wrapper
from tink.python.core import tink_error
from tink.python.signature import public_key_sign


class _WrappedPublicKeySign(public_key_sign.PublicKeySign):
  """Implements PublicKeySign for a set of PublicKeySign primitives."""

  def __init__(self, primitives_set: primitive_set.PrimitiveSet):
    self._primitive_set = primitives_set

  def sign(self, data: bytes) -> bytes:
    """Computes the signature for data using the primary primitive.

    Args:
      data: The input data.

    Returns:
      The signature.
    """
    primary = self._primitive_set.primary()

    if not primary:
      raise tink_error.TinkError('primary primitive not set')

    sign_data = data
    if primary.output_prefix_type == tink_pb2.LEGACY:
      sign_data = sign_data + crypto_format.LEGACY_START_BYTE

    return primary.identifier + primary.primitive.sign(sign_data)


class PublicKeySignWrapper(
    primitive_wrapper.PrimitiveWrapper[public_key_sign.PublicKeySign]):
  """A PrimitiveWrapper for the PublicKeySign primitive.

  The returned primitive works with a keyset (rather than a single key). To sign
  a message, it uses the primary key in the keyset, and prepends to the
  signature a certain prefix associated with the primary key.
  """

  def wrap(self, primitives_set: primitive_set.PrimitiveSet
          ) -> _WrappedPublicKeySign:
    return _WrappedPublicKeySign(primitives_set)

  def primitive_class(self) -> Type[public_key_sign.PublicKeySign]:
    return public_key_sign.PublicKeySign
