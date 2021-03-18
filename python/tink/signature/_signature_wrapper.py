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
# Placeholder for import for type annotations
from __future__ import print_function

from typing import Type
from absl import logging

from tink.proto import tink_pb2
from tink import core
from tink.signature import _public_key_sign
from tink.signature import _public_key_verify


class _WrappedPublicKeySign(_public_key_sign.PublicKeySign):
  """Implements PublicKeySign for a set of PublicKeySign primitives."""

  def __init__(self, primitives_set: core.PrimitiveSet):
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
      raise core.TinkError('primary primitive not set')

    sign_data = data
    if primary.output_prefix_type == tink_pb2.LEGACY:
      sign_data = sign_data + b'\x00'

    return primary.identifier + primary.primitive.sign(sign_data)


class PublicKeySignWrapper(
    core.PrimitiveWrapper[_public_key_sign.PublicKeySign,
                          _public_key_sign.PublicKeySign]):
  """A PrimitiveWrapper for the PublicKeySign primitive.

  The returned primitive works with a keyset (rather than a single key). To sign
  a message, it uses the primary key in the keyset, and prepends to the
  signature a certain prefix associated with the primary key.
  """

  def wrap(self, primitives_set: core.PrimitiveSet
          ) -> _WrappedPublicKeySign:
    return _WrappedPublicKeySign(primitives_set)

  def primitive_class(self) -> Type[_public_key_sign.PublicKeySign]:
    return _public_key_sign.PublicKeySign

  def input_primitive_class(self) -> Type[_public_key_sign.PublicKeySign]:
    return _public_key_sign.PublicKeySign


class _WrappedPublicKeyVerify(_public_key_verify.PublicKeyVerify):
  """Implements PublicKeyVerify for a set of PublicKeyVerify primitives."""

  def __init__(self, primitives_set: core.PrimitiveSet):
    self._primitive_set = primitives_set

  def verify(self, signature: bytes, data: bytes):
    """Verifies that signature is a digital signature for data.

    Args:
      signature: The signature bytes to be checked.
      data: The data bytes to be checked.

    Raises:
      tink_error.TinkError if the verification fails.
    """
    if len(signature) <= core.crypto_format.NON_RAW_PREFIX_SIZE:
      # This also rejects raw signatures with size of 4 bytes or fewer.
      # We're not aware of any schemes that output signatures that small.
      raise core.TinkError('signature too short')

    key_id = signature[:core.crypto_format.NON_RAW_PREFIX_SIZE]
    raw_sig = signature[core.crypto_format.NON_RAW_PREFIX_SIZE:]

    for entry in self._primitive_set.primitive_from_identifier(key_id):
      try:
        if entry.output_prefix_type == tink_pb2.LEGACY:
          entry.primitive.verify(raw_sig, data + b'\x00')
        else:
          entry.primitive.verify(raw_sig, data)
        # Signature is valid, we can return
        return
      except core.TinkError as err:
        logging.info('signature prefix matches a key, but cannot verify: %s',
                     err)

    # No matching key succeeded with verification, try all RAW keys
    for entry in self._primitive_set.raw_primitives():
      try:
        entry.primitive.verify(signature, data)
        # Signature is valid, we can return
        return
      except core.TinkError:
        pass

    raise core.TinkError('invalid signature')


class PublicKeyVerifyWrapper(
    core.PrimitiveWrapper[_public_key_verify.PublicKeyVerify,
                          _public_key_verify.PublicKeyVerify]):
  """WrappedPublicKeyVerify is the PrimitiveWrapper for PublicKeyVerify.

  The returned primitive works with a keyset (rather than a single key). To sign
  a message, it uses the primary key in the keyset, and prepends to the
  signature a certain prefix associated with the primary key.

  The returned primitive works with a keyset (rather than a single key). To
  verify a signature, the primitive uses the prefix of the signature to
  efficiently select the right key in the set. If there is no key associated
  with the prefix or if the keys associated with the prefix do not work, the
  primitive tries all keys with tink_pb2.OutputPrefixType = tink_pb2.RAW.
  """

  def wrap(self, primitives_set: core.PrimitiveSet
          ) -> _WrappedPublicKeyVerify:
    return _WrappedPublicKeyVerify(primitives_set)

  def primitive_class(self) -> Type[_public_key_verify.PublicKeyVerify]:
    return _public_key_verify.PublicKeyVerify

  def input_primitive_class(self) -> Type[_public_key_verify.PublicKeyVerify]:
    return _public_key_verify.PublicKeyVerify
