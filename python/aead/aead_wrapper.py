# Copyright 2019 Google LLC.
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

"""AEAD wrapper."""

from __future__ import absolute_import
from __future__ import division
from __future__ import google_type_annotations
from __future__ import print_function

from absl import logging

from typing import Type

from tink.python.aead import aead
from tink.python.core import crypto_format
from tink.python.core import primitive_set
from tink.python.core import primitive_wrapper
from tink.python.core import tink_error


class _WrappedAead(aead.Aead):
  """Implements Aead for a set of Aead primitives."""

  def __init__(self, pset: primitive_set.PrimitiveSet):
    self._primitive_set = pset

  def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
    primary = self._primitive_set.primary()
    return primary.identifier + primary.primitive.encrypt(
        plaintext, associated_data)

  def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes:
    if len(ciphertext) > crypto_format.NON_RAW_PREFIX_SIZE:
      prefix = ciphertext[:crypto_format.NON_RAW_PREFIX_SIZE]
      ciphertext_no_prefix = ciphertext[crypto_format.NON_RAW_PREFIX_SIZE:]
      for entry in self._primitive_set.primitive_from_identifier(prefix):
        try:
          return entry.primitive.decrypt(ciphertext_no_prefix,
                                         associated_data)
        except tink_error.TinkError as e:
          logging.info(
              'ciphertext prefix matches a key, but cannot decrypt: %s', e)
    # Let's try all RAW keys.
    for entry in self._primitive_set.raw_primitives():
      try:
        return entry.primitive.decrypt(ciphertext, associated_data)
      except tink_error.TinkError as e:
        pass
    # nothing works.
    raise tink_error.TinkError('Decryption failed.')


class AeadWrapper(primitive_wrapper.PrimitiveWrapper[aead.Aead]):
  """AeadWrapper is the implementation of PrimitiveWrapper for Aead.

  Key rotation works as follows: each ciphertext is prefixed with the keyId.
  When decrypting, we first try all primitives whose keyId starts with the
  prefix of the ciphertext. If none of these succeed, we try the raw primitives.
  If any succeeds, we return the ciphertext, otherwise we simply raise a
  TinkError.
  """

  def wrap(self, pset: primitive_set.PrimitiveSet) -> aead.Aead:
    return _WrappedAead(pset)

  def primitive_class(self) -> Type[aead.Aead]:
    return aead.Aead
