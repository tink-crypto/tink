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

"""Reads Keysets from file."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import abc

from typing import Text
# Special imports
import six


from tink.proto import tink_pb2
from tink import core
from google.protobuf import json_format
from google.protobuf import message


@six.add_metaclass(abc.ABCMeta)
class KeysetReader(object):
  """Reads a Keyset."""

  @abc.abstractmethod
  def read(self) -> tink_pb2.Keyset:
    """Reads and returns a (cleartext) tink_pb2.Keyset from its source."""
    raise NotImplementedError()

  @abc.abstractmethod
  def read_encrypted(self) -> tink_pb2.EncryptedKeyset:
    """Reads and returns an tink_pb2.EncryptedKeyset from its source."""
    raise NotImplementedError()


class JsonKeysetReader(KeysetReader):
  """Reads a JSON Keyset."""

  def __init__(self, serialized_keyset: Text):
    self._serialized_keyset = serialized_keyset

  def read(self) -> tink_pb2.Keyset:
    try:
      return json_format.Parse(self._serialized_keyset, tink_pb2.Keyset())
    except json_format.ParseError as e:
      raise core.TinkError(e)

  def read_encrypted(self) -> tink_pb2.EncryptedKeyset:
    try:
      return json_format.Parse(self._serialized_keyset,
                               tink_pb2.EncryptedKeyset())
    except json_format.ParseError as e:
      raise core.TinkError(e)


class BinaryKeysetReader(KeysetReader):
  """Reads a binary Keyset."""

  def __init__(self, serialized_keyset: bytes):
    self._serialized_keyset = serialized_keyset

  def read(self) -> tink_pb2.Keyset:
    if not self._serialized_keyset:
      raise core.TinkError('No keyset found')
    try:
      return tink_pb2.Keyset.FromString(self._serialized_keyset)
    except message.DecodeError as e:
      raise core.TinkError(e)

  def read_encrypted(self) -> tink_pb2.EncryptedKeyset:
    if not self._serialized_keyset:
      raise core.TinkError('No keyset found')
    try:
      return tink_pb2.EncryptedKeyset.FromString(self._serialized_keyset)
    except message.DecodeError as e:
      raise core.TinkError(e)
