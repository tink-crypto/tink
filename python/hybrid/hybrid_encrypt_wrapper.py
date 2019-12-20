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

"""HybridEncrypt wrapper."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from typing import Type

from tink.python.core import primitive_set
from tink.python.core import primitive_wrapper
from tink.python.hybrid import hybrid_encrypt


class _WrappedHybridEncrypt(hybrid_encrypt.HybridEncrypt):
  """Implements HybridEncrypt for a set of HybridEncrypt primitives."""

  def __init__(self, pset: primitive_set.PrimitiveSet):
    self._primitive_set = pset

  def encrypt(self, plaintext: bytes, context_info: bytes) -> bytes:
    primary = self._primitive_set.primary()
    return primary.identifier + primary.primitive.encrypt(
        plaintext, context_info)


class HybridEncryptWrapper(
    primitive_wrapper.PrimitiveWrapper[hybrid_encrypt.HybridEncrypt]):
  """HybridEncryptWrapper is the PrimitiveWrapper for HybridEncrypt.

  The returned primitive works with a keyset (rather than a single key). To
  encrypt a plaintext, it uses the primary key in the keyset, and prepends to
  the ciphertext a certain prefix associated with the primary key.
  """

  def wrap(self,
           pset: primitive_set.PrimitiveSet) -> hybrid_encrypt.HybridEncrypt:
    return _WrappedHybridEncrypt(pset)

  def primitive_class(self) -> Type[hybrid_encrypt.HybridEncrypt]:
    return hybrid_encrypt.HybridEncrypt
