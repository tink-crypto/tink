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

"""A container class for a set of primitives."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import collections
from typing import Generic, List, Type, TypeVar

from tink.proto import tink_pb2
from tink.core import _crypto_format
from tink.core import _tink_error

P = TypeVar('P')
Entry = collections.namedtuple(
    'Entry', 'primitive, identifier, status, output_prefix_type, key_id')


def new_primitive_set(primitive_class):
  return PrimitiveSet(primitive_class)


class PrimitiveSet(Generic[P]):
  """A container class for a set of primitives.

  PrimitiveSet is an auxiliary class used for supporting key rotation:
  primitives in a set correspond to keys in a keyset. Users will usually work
  with primitive instances, which essentially wrap primitive sets. For example
  an instance of an Aead-primitive for a given keyset holds a set of
  Aead-primitives corresponding to the keys in the keyset, and uses the set
  members to do the actual crypto operations: to encrypt data the primary
  Aead-primitive from the set is used, and upon decryption the ciphertext's
  prefix determines the id of the primitive from the set.
  """

  def __init__(self, primitive_class: Type[P]):
    self._primitives = {}  # Dict[bytes, List[Entry]]
    self._primary = None
    self._primitive_class = primitive_class

  def primitive_class(self) -> Type[P]:
    return self._primitive_class

  def primitive_from_identifier(self, identifier: bytes) -> List[Entry]:
    """Returns a copy of the list of entries for a given identifier."""
    # Copy the list so that if the user modifies the list, it does not affect
    # the internal data structure.
    return self._primitives.get(identifier, [])[:]

  def all(self) -> List[List[Entry]]:
    """Returns a list of copies of all lists of entries in the primitive set."""
    return list(entries[:] for entries in self._primitives.values())

  def primitive(self, key: tink_pb2.Keyset.Key) -> List[Entry]:
    """Returns a copy of the list of entries for a given key."""
    return self.primitive_from_identifier(_crypto_format.output_prefix(key))

  def raw_primitives(self) -> List[Entry]:
    """Returns a copy of the list of entries of keys with raw prefix."""
    # All raw keys have the same identifier, which is just b''.
    return self.primitive_from_identifier(_crypto_format.RAW_PREFIX)

  def add_primitive(self, primitive: P, key: tink_pb2.Keyset.Key) -> Entry:
    """Adds a new primitive and key entry to the set, and returns the entry."""
    if not isinstance(primitive, self._primitive_class):
      raise _tink_error.TinkError(
          'The primitive is not an instance of {}'.format(
              self._primitive_class))
    identifier = _crypto_format.output_prefix(key)

    entry = Entry(primitive, identifier, key.status, key.output_prefix_type,
                  key.key_id)
    entries = self._primitives.setdefault(identifier, [])
    entries.append(entry)
    return entry

  def set_primary(self, entry: Entry) -> None:
    self._primary = entry

  def primary(self) -> Entry:
    return self._primary
