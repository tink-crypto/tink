# Copyright 2020 Google LLC
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
"""PrfSet wrapper."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from typing import Type, Mapping
from tink import core
from tink.prf import _prf_set


class _WrappedPrfSet(_prf_set.PrfSet):
  """Implements PrfSet for a set of PrfSet primitives."""

  def __init__(self, primitive_set: core.PrimitiveSet):
    self._primitive_set = primitive_set

  def primary_id(self) -> int:
    return self._primitive_set.primary().key_id

  def all(self) -> Mapping[int, _prf_set.Prf]:
    return {
        entry.key_id: entry.primitive
        for entry in self._primitive_set.raw_primitives()
    }

  def primary(self) -> _prf_set.Prf:
    return self._primitive_set.primary().primitive


class PrfSetWrapper(core.PrimitiveWrapper[_prf_set.Prf, _prf_set.PrfSet]):
  """A PrimitiveWrapper for the PrfSet primitive.

  The returned primitive works with a keyset (rather than a single key). To sign
  a message, it uses the primary key in the keyset, and prepends to the
  signature a certain prefix associated with the primary key.
  """

  def wrap(self, primitives_set: core.PrimitiveSet) -> _WrappedPrfSet:
    return _WrappedPrfSet(primitives_set)

  def primitive_class(self) -> Type[_prf_set.PrfSet]:
    return _prf_set.PrfSet

  def input_primitive_class(self) -> Type[_prf_set.Prf]:
    return _prf_set.Prf
