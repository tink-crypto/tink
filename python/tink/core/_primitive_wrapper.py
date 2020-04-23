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

"""Basic interface for wrapping a primitive."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import abc

# Special imports
import six

from typing import Generic, Type, TypeVar

from tink.core import _primitive_set


P = TypeVar('P')


@six.add_metaclass(abc.ABCMeta)
class PrimitiveWrapper(Generic[P]):
  """Basic interface for wrapping a primitive.

  A PrimitiveSet can be wrapped by a single primitive in order to fulfill a
  cryptographic task. This is done by the PrimitiveWrapper. Whenever a new
  primitive type is added to Tink, the user should define a new PrimitiveWrapper
  and register it by calling registry.registerPrimitiveWrapper().
  """

  @abc.abstractmethod
  def wrap(self, pset: _primitive_set.PrimitiveSet) -> P:
    """Wraps a PrimitiveSet and returns a single primitive instance."""
    pass

  @abc.abstractmethod
  def primitive_class(self) -> Type[P]:
    """Returns the primitive class of the primitive managed."""
    pass
