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

"""Public Key Verify wrapper."""

from __future__ import absolute_import
from __future__ import division
from __future__ import google_type_annotations
from __future__ import print_function

from absl import logging
from typing import Type

from tink.proto import tink_pb2
from tink.python.core import crypto_format
from tink.python.core import primitive_set
from tink.python.core import primitive_wrapper
from tink.python.core import tink_error
from tink.python.signature import public_key_verify


class _WrappedPublicKeyVerify(public_key_verify.PublicKeyVerify):
  """Implements PublicKeyVerify for a set of PublicKeyVerify primitives."""

  def __init__(self, primitives_set: primitive_set.PrimitiveSet):
    self._primitive_set = primitives_set

  def verify(self, signature: bytes, data: bytes):
    """Verifies that signature is a digital signature for data.

    Args:
      signature: The signature bytes to be checked.
      data: The data bytes to be checked.

    Raises:
      tink_error.TinkError if the verification fails.
    """
    if len(signature) <= crypto_format.NON_RAW_PREFIX_SIZE:
      # This also rejects raw signatures with size of 4 bytes or fewer.
      # We're not aware of any schemes that output signatures that small.
      raise tink_error.TinkError('signature too short')

    key_id = signature[:crypto_format.NON_RAW_PREFIX_SIZE]
    raw_sig = signature[crypto_format.NON_RAW_PREFIX_SIZE:]

    for entry in self._primitive_set.primitive_from_identifier(key_id):
      try:
        if entry.output_prefix_type == tink_pb2.LEGACY:
          entry.primitive.verify(raw_sig,
                                 data + crypto_format.LEGACY_START_BYTE)
        else:
          entry.primitive.verify(raw_sig, data)
        # Signature is valid, we can return
        return
      except tink_error.TinkError as err:
        logging.info('signature prefix matches a key, but cannot verify: %s',
                     err)

    # No matching key succeeded with verification, try all RAW keys
    for entry in self._primitive_set.raw_primitives():
      try:
        entry.primitive.verify(signature, data)
        # Signature is valid, we can return
        return
      except tink_error.TinkError:
        pass

    raise tink_error.TinkError('invalid signature')


class PublicKeyVerifyWrapper(
    primitive_wrapper.PrimitiveWrapper[public_key_verify.PublicKeyVerify]):
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

  def wrap(self, primitives_set: primitive_set.PrimitiveSet
          ) -> _WrappedPublicKeyVerify:
    return _WrappedPublicKeyVerify(primitives_set)

  def primitive_class(self) -> Type[public_key_verify.PublicKeyVerify]:
    return public_key_verify.PublicKeyVerify
