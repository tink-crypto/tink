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

"""This module defines KeysetHandle."""

from __future__ import absolute_import
from __future__ import division
from __future__ import google_type_annotations
from __future__ import print_function

import random

from typing import Type, TypeVar

from google.protobuf import message
from tink.proto import tink_pb2
from tink.python.aead import aead
from tink.python.core import keyset_reader as reader
from tink.python.core import keyset_writer as writer
from tink.python.core import primitive_set
from tink.python.core import registry
from tink.python.core import tink_error

P = TypeVar('P')

MAX_INT32 = 2147483647  # = 2^31 - 1


class KeysetHandle(object):
  """A KeysetHandle provides abstracted access to Keyset.

  KeysetHandle limits the exposure of actual protocol buffers that hold
  sensitive key material. This class allows reading and writing encrypted
  keysets.
  """

  def __init__(self, keyset: tink_pb2.Keyset):
    self._keyset = keyset

  def keyset_info(self) -> tink_pb2.KeysetInfo:
    """Returns the KeysetInfo that doesn't contain actual key material."""
    return _keyset_info(self._keyset)

  def write(self, keyset_writer: writer.KeysetWriter,
            master_key_primitive: aead.Aead) -> None:
    """Serializes, encrypts with master_key_primitive and writes the keyset."""
    encrypted_keyset = _encrypt(self._keyset, master_key_primitive)
    keyset_writer.write_encrypted(encrypted_keyset)

  def public_keyset_handle(self) -> 'KeysetHandle':
    """Returns a new KeysetHandle for the corresponding public keys."""
    public_keyset = tink_pb2.Keyset()
    for key in self._keyset.key:
      public_key = public_keyset.key.add()
      public_key.CopyFrom(key)
      public_key.key_data.CopyFrom(
          registry.Registry.public_key_data(key.key_data))
      _validate_key(public_key)
    public_keyset.primary_key_id = self._keyset.primary_key_id
    return KeysetHandle(public_keyset)

  def primitive(self, primitive_class: Type[P]) -> P:
    """Returns a wrapped primitive from this KeysetHandle.

    Uses the KeyManager and the PrimitiveWrapper objects in the global
    registry.Registry
    to create the primitive. This function is the most common way of creating a
    primitive.

    Args:
      primitive_class: The class of the primitive.

    Returns:
      The primitive.
    Raises:
      tink.TinkError if creation of the primitive fails, for example if
      primitive_class cannot be used with this KeysetHandle.
    """
    _validate_keyset(self._keyset)
    pset = primitive_set.PrimitiveSet(primitive_class)
    for key in self._keyset.key:
      if key.status == tink_pb2.ENABLED:
        primitive = registry.Registry.primitive(key.key_data, primitive_class)
        entry = pset.add_primitive(primitive, key)
        if key.key_id == self._keyset.primary_key_id:
          pset.set_primary(entry)
    return registry.Registry.wrap(pset)


def generate_new(key_template: tink_pb2.KeyTemplate) -> KeysetHandle:
  """Return a new KeysetHandle.

  It contains a single fresh key generated according to key_template.

  Args:
    key_template: A tink_pb2.KeyTemplate object.

  Returns:
    A new KeysetHandle.
  """
  keyset = tink_pb2.Keyset()
  key_data = registry.Registry.new_key_data(key_template)
  key_id = _generate_unused_key_id(keyset)
  key = keyset.key.add()
  key.key_data.CopyFrom(key_data)
  key.status = tink_pb2.ENABLED
  key.key_id = key_id
  key.output_prefix_type = key_template.output_prefix_type
  keyset.primary_key_id = key_id
  return KeysetHandle(keyset)


def read(keyset_reader: reader.KeysetReader,
         master_key_aead: aead.Aead) -> KeysetHandle:
  """Tries to create a KeysetHandle from an encrypted keyset."""
  encrypted_keyset = keyset_reader.read_encrypted()
  _assert_enough_encrypted_key_material(encrypted_keyset)
  return KeysetHandle(_decrypt(encrypted_keyset, master_key_aead))


def _keyset_info(keyset: tink_pb2.Keyset) -> tink_pb2.KeysetInfo:
  keyset_info = tink_pb2.KeysetInfo(primary_key_id=keyset.primary_key_id)
  for key in keyset.key:
    key_info = keyset_info.key_info.add()
    key_info.type_url = key.key_data.type_url
    key_info.status = key.status
    key_info.output_prefix_type = key.output_prefix_type
    key_info.key_id = key.key_id
  return keyset_info


def _encrypt(keyset: tink_pb2.Keyset,
             master_key_primitive: aead.Aead) -> tink_pb2.EncryptedKeyset:
  """Encrypts a Keyset and returns an EncryptedKeyset."""
  encrypted_keyset = master_key_primitive.encrypt(keyset.SerializeToString(),
                                                  b'')
  # Check if we can decrypt, to detect errors
  try:
    keyset2 = tink_pb2.Keyset.FromString(
        master_key_primitive.decrypt(encrypted_keyset, b''))
    if keyset != keyset2:
      raise tink_error.TinkError('cannot encrypt keyset: %s != %s' %
                                 (keyset, keyset2))
  except message.DecodeError:
    raise tink_error.TinkError('invalid keyset, corrupted key material')
  return tink_pb2.EncryptedKeyset(
      encrypted_keyset=encrypted_keyset, keyset_info=_keyset_info(keyset))


def _decrypt(encrypted_keyset: tink_pb2.EncryptedKeyset,
             master_key_aead: aead.Aead) -> tink_pb2.Keyset:
  """Decrypts an EncryptedKeyset and returns a Keyset."""
  try:
    keyset = tink_pb2.Keyset.FromString(
        master_key_aead.decrypt(encrypted_keyset.encrypted_keyset, b''))
    # Check emptiness here too, in case the encrypted keys unwrapped to nothing?
    _assert_enough_key_material(keyset)
    return keyset
  except message.DecodeError:
    raise tink_error.TinkError('invalid keyset, corrupted key material')


def _validate_keyset(keyset: tink_pb2.Keyset):
  """Raises tink_error.TinkError if keyset is not valid."""
  for key in keyset.key:
    if key.status != tink_pb2.DESTROYED:
      _validate_key(key)
  num_non_destroyed_keys = sum(
      1 for key in keyset.key if key.status != tink_pb2.DESTROYED)
  num_non_public_key_material = sum(
      1 for key in keyset.key
      if key.key_data.key_material_type != tink_pb2.KeyData.ASYMMETRIC_PUBLIC)
  num_primary_keys = sum(
      1 for key in keyset.key
      if key.status == tink_pb2.ENABLED and key.key_id == keyset.primary_key_id)
  if num_non_destroyed_keys == 0:
    raise tink_error.TinkError('empty keyset')
  if num_primary_keys > 1:
    raise tink_error.TinkError('keyset contains multiple primary keys')
  if num_primary_keys == 0 and num_non_public_key_material > 0:
    raise tink_error.TinkError('keyset does not contain a valid primary key')


def _validate_key(key: tink_pb2.Keyset.Key):
  """Raises tink_error.TinkError if key is not valid."""
  if not key.HasField('key_data'):
    raise tink_error.TinkError('key {} has no key data'.format(key.key_id))
  if key.output_prefix_type == tink_pb2.UNKNOWN_PREFIX:
    raise tink_error.TinkError('key {} has unknown prefix'.format(key.key_id))
  if key.status == tink_pb2.UNKNOWN_STATUS:
    raise tink_error.TinkError('key {} has unknown status'.format(key.key_id))


def _assert_no_secret_key_material(keyset: tink_pb2.Keyset):
  for key in keyset.key:
    if (key.key_data.key_material_type == tink_pb2.KeyData.UNKNOWN_KEYMATERIAL
        or key.key_data.key_material_type == tink_pb2.KeyData.SYMMETRIC or
        key.key_data.key_material_type == tink_pb2.KeyData.ASYMMETRIC_PRIVATE):
      raise tink_error.TinkError('keyset contains secret key material')


def _assert_enough_key_material(keyset: tink_pb2.Keyset):
  if not keyset or not keyset.key:
    raise tink_error.TinkError('empty keyset')


def _assert_enough_encrypted_key_material(
    encrypted_keyset: tink_pb2.EncryptedKeyset):
  if not encrypted_keyset or not encrypted_keyset.encrypted_keyset:
    raise tink_error.TinkError('empty keyset')


def _generate_unused_key_id(keyset: tink_pb2.Keyset) -> int:
  while True:
    key_id = random.randint(1, MAX_INT32)
    if key_id not in {key.key_id for key in keyset.key}:
      return key_id
