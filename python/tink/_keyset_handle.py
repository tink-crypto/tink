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
# Placeholder for import for type annotations
from __future__ import print_function

import random

from typing import Type, TypeVar

from google.protobuf import message
from tink.proto import tink_pb2
from tink import _keyset_reader
from tink import _keyset_writer
from tink import aead
from tink import core

P = TypeVar('P')

MAX_INT32 = 2147483647  # = 2^31 - 1


class KeysetHandle(object):
  """A KeysetHandle provides abstracted access to Keyset.

  KeysetHandle limits the exposure of actual protocol buffers that hold
  sensitive key material. This class allows reading and writing encrypted
  keysets.
  """

  def __new__(cls):
    raise core.TinkError(('KeysetHandle cannot be instantiated directly.'))

  def __init__(self, keyset: tink_pb2.Keyset):
    _validate_keyset(keyset)
    self._keyset = keyset

  @classmethod
  def generate_new(cls, key_template: tink_pb2.KeyTemplate) -> 'KeysetHandle':
    """Return a new KeysetHandle.

    It contains a single fresh key generated according to key_template.

    Args:
      key_template: A tink_pb2.KeyTemplate object.

    Returns:
      A new KeysetHandle.
    """
    keyset = tink_pb2.Keyset()
    key_data = core.Registry.new_key_data(key_template)
    key_id = _generate_unused_key_id(keyset)
    key = keyset.key.add()
    key.key_data.CopyFrom(key_data)
    key.status = tink_pb2.ENABLED
    key.key_id = key_id
    key.output_prefix_type = key_template.output_prefix_type
    keyset.primary_key_id = key_id
    return cls._create(keyset)

  @classmethod
  def read(cls, keyset_reader: _keyset_reader.KeysetReader,
           master_key_aead: aead.Aead) -> 'KeysetHandle':
    """Tries to create a KeysetHandle from an encrypted keyset."""
    return cls.read_with_associated_data(keyset_reader, master_key_aead, b'')

  @classmethod
  def read_with_associated_data(cls, keyset_reader: _keyset_reader.KeysetReader,
                                master_key_aead: aead.Aead,
                                associated_data: bytes) -> 'KeysetHandle':
    """Tries to create a KeysetHandle from an encrypted keyset using the provided associated data."""
    encrypted_keyset = keyset_reader.read_encrypted()
    _assert_enough_encrypted_key_material(encrypted_keyset)
    return cls._create(
        _decrypt(encrypted_keyset, master_key_aead, associated_data))

  @classmethod
  def read_no_secret(
      cls, keyset_reader: _keyset_reader.KeysetReader) -> 'KeysetHandle':
    """Creates a KeysetHandle from a keyset with no secret key material.

    This can be used to load public keysets or envelope encryption keysets.

    Args:
      keyset_reader: A _keyset_reader.KeysetReader object.

    Returns:
      A new KeysetHandle.
    """
    keyset = keyset_reader.read()
    _assert_no_secret_key_material(keyset)
    return cls._create(keyset)

  @classmethod
  def _create(cls, keyset: tink_pb2.Keyset):
    o = object.__new__(cls)
    o.__init__(keyset)
    return o

  def keyset_info(self) -> tink_pb2.KeysetInfo:
    """Returns the KeysetInfo that doesn't contain actual key material."""
    return _keyset_info(self._keyset)

  def write(self, keyset_writer: _keyset_writer.KeysetWriter,
            master_key_primitive: aead.Aead) -> None:
    """Serializes, encrypts with master_key_primitive and writes the keyset."""
    self.write_with_associated_data(keyset_writer, master_key_primitive, b'')

  def write_with_associated_data(self,
                                 keyset_writer: _keyset_writer.KeysetWriter,
                                 master_key_primitive: aead.Aead,
                                 associated_data: bytes) -> None:
    """Serializes, encrypts with master_key_primitive and writes the keyset."""
    encrypted_keyset = _encrypt(self._keyset, master_key_primitive,
                                associated_data)
    keyset_writer.write_encrypted(encrypted_keyset)

  def write_no_secret(self, keyset_writer: _keyset_writer.KeysetWriter) -> None:
    """Writes the underlying keyset to keyset_writer.

    Writes the underlying keyset to keyset_writer only if the keyset does not
    contain any secret key material.
    This can be used to persist public keysets or envelope encryption keysets.
    Users that need to persist keysets with secret material can use
    cleartext_keyset_handle.

    Args:
      keyset_writer: A KeysetWriter object.
    """
    _assert_no_secret_key_material(self._keyset)
    keyset_writer.write(self._keyset)

  def public_keyset_handle(self) -> 'KeysetHandle':
    """Returns a new KeysetHandle for the corresponding public keys."""
    public_keyset = tink_pb2.Keyset()
    for key in self._keyset.key:
      public_key = public_keyset.key.add()
      public_key.CopyFrom(key)
      public_key.key_data.CopyFrom(core.Registry.public_key_data(key.key_data))
      _validate_key(public_key)
    public_keyset.primary_key_id = self._keyset.primary_key_id
    return self._create(public_keyset)

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
    input_primitive_class = core.Registry.input_primitive_class(primitive_class)
    pset = core.PrimitiveSet(input_primitive_class)
    for key in self._keyset.key:
      if key.status == tink_pb2.ENABLED:
        primitive = core.Registry.primitive(key.key_data, input_primitive_class)
        entry = pset.add_primitive(primitive, key)
        if key.key_id == self._keyset.primary_key_id:
          pset.set_primary(entry)
    return core.Registry.wrap(pset, primitive_class)


def new_keyset_handle(key_template: tink_pb2.KeyTemplate) -> KeysetHandle:
  return KeysetHandle.generate_new(key_template)


def read_keyset_handle(keyset_reader: _keyset_reader.KeysetReader,
                       master_key_aead: aead.Aead) -> KeysetHandle:
  return KeysetHandle.read(keyset_reader, master_key_aead)


def read_keyset_handle_with_associated_data(
    keyset_reader: _keyset_reader.KeysetReader, master_key_aead: aead.Aead,
    associated_data: bytes) -> KeysetHandle:
  return KeysetHandle.read_with_associated_data(keyset_reader, master_key_aead,
                                                associated_data)


def read_no_secret_keyset_handle(
    keyset_reader: _keyset_reader.KeysetReader) -> KeysetHandle:
  return KeysetHandle.read_no_secret(keyset_reader)


def _keyset_info(keyset: tink_pb2.Keyset) -> tink_pb2.KeysetInfo:
  keyset_info = tink_pb2.KeysetInfo(primary_key_id=keyset.primary_key_id)
  for key in keyset.key:
    key_info = keyset_info.key_info.add()
    key_info.type_url = key.key_data.type_url
    key_info.status = key.status
    key_info.output_prefix_type = key.output_prefix_type
    key_info.key_id = key.key_id
  return keyset_info


def _encrypt(keyset: tink_pb2.Keyset, master_key_primitive: aead.Aead,
             associated_data: bytes) -> tink_pb2.EncryptedKeyset:
  """Encrypts a Keyset and returns an EncryptedKeyset."""
  encrypted_keyset = master_key_primitive.encrypt(keyset.SerializeToString(),
                                                  associated_data)
  # Check if we can decrypt, to detect errors
  try:
    keyset2 = tink_pb2.Keyset.FromString(
        master_key_primitive.decrypt(encrypted_keyset, associated_data))
    if keyset != keyset2:
      raise core.TinkError('cannot encrypt keyset: %s != %s' %
                           (keyset, keyset2))
  except message.DecodeError:
    raise core.TinkError('invalid keyset, corrupted key material')
  return tink_pb2.EncryptedKeyset(
      encrypted_keyset=encrypted_keyset, keyset_info=_keyset_info(keyset))


def _decrypt(encrypted_keyset: tink_pb2.EncryptedKeyset,
             master_key_aead: aead.Aead,
             associated_data: bytes) -> tink_pb2.Keyset:
  """Decrypts an EncryptedKeyset and returns a Keyset."""
  try:
    keyset = tink_pb2.Keyset.FromString(
        master_key_aead.decrypt(encrypted_keyset.encrypted_keyset,
                                associated_data))
    # Check emptiness here too, in case the encrypted keys unwrapped to nothing?
    _assert_enough_key_material(keyset)
    return keyset
  except message.DecodeError:
    raise core.TinkError('invalid keyset, corrupted key material')


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
    raise core.TinkError('empty keyset')
  if num_primary_keys > 1:
    raise core.TinkError('keyset contains multiple primary keys')
  if num_primary_keys == 0 and num_non_public_key_material > 0:
    raise core.TinkError('keyset does not contain a valid primary key')


def _validate_key(key: tink_pb2.Keyset.Key):
  """Raises tink_error.TinkError if key is not valid."""
  if not key.HasField('key_data'):
    raise core.TinkError('key {} has no key data'.format(key.key_id))
  if key.output_prefix_type == tink_pb2.UNKNOWN_PREFIX:
    raise core.TinkError('key {} has unknown prefix'.format(key.key_id))
  if key.status == tink_pb2.UNKNOWN_STATUS:
    raise core.TinkError('key {} has unknown status'.format(key.key_id))


def _assert_no_secret_key_material(keyset: tink_pb2.Keyset):
  for key in keyset.key:
    if key.key_data.key_material_type in (tink_pb2.KeyData.UNKNOWN_KEYMATERIAL,
                                          tink_pb2.KeyData.SYMMETRIC,
                                          tink_pb2.KeyData.ASYMMETRIC_PRIVATE):
      raise core.TinkError('keyset contains secret key material')


def _assert_enough_key_material(keyset: tink_pb2.Keyset):
  if not keyset or not keyset.key:
    raise core.TinkError('empty keyset')


def _assert_enough_encrypted_key_material(
    encrypted_keyset: tink_pb2.EncryptedKeyset):
  if not encrypted_keyset or not encrypted_keyset.encrypted_keyset:
    raise core.TinkError('empty keyset')


def _generate_unused_key_id(keyset: tink_pb2.Keyset) -> int:
  while True:
    key_id = random.randint(1, MAX_INT32)
    if key_id not in {key.key_id for key in keyset.key}:
      return key_id
