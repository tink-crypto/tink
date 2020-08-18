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

"""HybridDecrypt wrapper."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from typing import Type
from absl import logging

from tink import core
from tink.hybrid import _hybrid_decrypt
from tink.hybrid import _hybrid_encrypt


class _WrappedHybridDecrypt(_hybrid_decrypt.HybridDecrypt):
  """Implements HybridDecrypt for a set of HybridDecrypt primitives."""

  def __init__(self, pset: core.PrimitiveSet):
    self._primitive_set = pset

  def decrypt(self, ciphertext: bytes, context_info: bytes) -> bytes:
    if len(ciphertext) > core.crypto_format.NON_RAW_PREFIX_SIZE:
      prefix = ciphertext[:core.crypto_format.NON_RAW_PREFIX_SIZE]
      ciphertext_no_prefix = ciphertext[core.crypto_format.NON_RAW_PREFIX_SIZE:]
      for entry in self._primitive_set.primitive_from_identifier(prefix):
        try:
          return entry.primitive.decrypt(ciphertext_no_prefix,
                                         context_info)
        except core.TinkError as e:
          logging.info(
              'ciphertext prefix matches a key, but cannot decrypt: %s', e)
    # Let's try all RAW keys.
    for entry in self._primitive_set.raw_primitives():
      try:
        return entry.primitive.decrypt(ciphertext, context_info)
      except core.TinkError as e:
        pass
    # nothing works.
    raise core.TinkError('Decryption failed.')


class HybridDecryptWrapper(core.PrimitiveWrapper[_hybrid_decrypt.HybridDecrypt,
                                                 _hybrid_decrypt.HybridDecrypt]
                          ):
  """HybridDecryptWrapper is the PrimitiveWrapper for HybridDecrypt.

  The returned primitive works with a keyset (rather than a single key). To
  decrypt, the primitive uses the prefix of the ciphertext to efficiently select
  the right key in the set. If the keys associated with the prefix do not work,
  the primitive tries all keys with OutputPrefixType RAW.
  """

  def wrap(self,
           pset: core.PrimitiveSet) -> _hybrid_decrypt.HybridDecrypt:
    return _WrappedHybridDecrypt(pset)

  def primitive_class(self) -> Type[_hybrid_decrypt.HybridDecrypt]:
    return _hybrid_decrypt.HybridDecrypt

  def input_primitive_class(self) -> Type[_hybrid_decrypt.HybridDecrypt]:
    return _hybrid_decrypt.HybridDecrypt


class _WrappedHybridEncrypt(_hybrid_encrypt.HybridEncrypt):
  """Implements HybridEncrypt for a set of HybridEncrypt primitives."""

  def __init__(self, pset: core.PrimitiveSet):
    self._primitive_set = pset

  def encrypt(self, plaintext: bytes, context_info: bytes) -> bytes:
    primary = self._primitive_set.primary()
    return primary.identifier + primary.primitive.encrypt(
        plaintext, context_info)


class HybridEncryptWrapper(core.PrimitiveWrapper[_hybrid_encrypt.HybridEncrypt,
                                                 _hybrid_encrypt.HybridEncrypt]
                          ):
  """HybridEncryptWrapper is the PrimitiveWrapper for HybridEncrypt.

  The returned primitive works with a keyset (rather than a single key). To
  encrypt a plaintext, it uses the primary key in the keyset, and prepends to
  the ciphertext a certain prefix associated with the primary key.
  """

  def wrap(self,
           pset: core.PrimitiveSet) -> _hybrid_encrypt.HybridEncrypt:
    return _WrappedHybridEncrypt(pset)

  def primitive_class(self) -> Type[_hybrid_encrypt.HybridEncrypt]:
    return _hybrid_encrypt.HybridEncrypt

  def input_primitive_class(self) -> Type[_hybrid_encrypt.HybridEncrypt]:
    return _hybrid_encrypt.HybridEncrypt
