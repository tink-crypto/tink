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

"""AEAD wrapper."""

from typing import Type

from tink import core
from tink.aead import _aead


class _WrappedAead(_aead.Aead):
  """Implements Aead for a set of Aead primitives."""

  def __init__(self, pset: core.PrimitiveSet):
    self._primitive_set = pset

  def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
    primary = self._primitive_set.primary()
    return primary.identifier + primary.primitive.encrypt(
        plaintext, associated_data)

  def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes:
    if len(ciphertext) > core.crypto_format.NON_RAW_PREFIX_SIZE:
      prefix = ciphertext[:core.crypto_format.NON_RAW_PREFIX_SIZE]
      ciphertext_no_prefix = ciphertext[core.crypto_format.NON_RAW_PREFIX_SIZE:]
      for entry in self._primitive_set.primitive_from_identifier(prefix):
        try:
          return entry.primitive.decrypt(ciphertext_no_prefix,
                                         associated_data)
        except core.TinkError:
          pass
    # Let's try all RAW keys.
    for entry in self._primitive_set.raw_primitives():
      try:
        return entry.primitive.decrypt(ciphertext, associated_data)
      except core.TinkError:
        pass
    # nothing works.
    raise core.TinkError('Decryption failed.')


class AeadWrapper(core.PrimitiveWrapper[_aead.Aead, _aead.Aead]):
  """AeadWrapper is the implementation of PrimitiveWrapper for Aead.

  Key rotation works as follows: each ciphertext is prefixed with the keyId.
  When decrypting, we first try all primitives whose keyId starts with the
  prefix of the ciphertext. If none of these succeed, we try the raw primitives.
  If any succeeds, we return the ciphertext, otherwise we simply raise a
  TinkError.
  """

  def wrap(self, pset: core.PrimitiveSet) -> _aead.Aead:
    return _WrappedAead(pset)

  def primitive_class(self) -> Type[_aead.Aead]:
    return _aead.Aead

  def input_primitive_class(self) -> Type[_aead.Aead]:
    return _aead.Aead
