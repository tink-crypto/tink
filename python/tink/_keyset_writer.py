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

"""Writes Keysets to file."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import abc

from typing import BinaryIO, TextIO
# Special imports
import six

from google.protobuf import json_format
from tink.proto import tink_pb2
from tink import core


@six.add_metaclass(abc.ABCMeta)
class KeysetWriter(object):
  """Knows how to write keysets to some storage system."""

  @abc.abstractmethod
  def write(self, keyset: tink_pb2.Keyset) -> None:
    """Tries to write a tink_pb2.Keyset to some storage system."""
    raise NotImplementedError()

  @abc.abstractmethod
  def write_encrypted(self, encrypted_keyset: tink_pb2.EncryptedKeyset) -> None:
    """Tries to write an tink_pb2.EncryptedKeyset to some storage system."""
    raise NotImplementedError()


class JsonKeysetWriter(KeysetWriter):
  """Writes keysets in proto JSON wire format to some storage system.

  cf. https://developers.google.com/protocol-buffers/docs/encoding
  """

  def __init__(self, text_io_stream: TextIO):
    self._io_stream = text_io_stream

  def write(self, keyset: tink_pb2.Keyset) -> None:
    if not isinstance(keyset, tink_pb2.Keyset):
      raise core.TinkError('invalid keyset.')
    json_keyset = json_format.MessageToJson(keyset)
    # TODO(b/141106504) Needed for python 2.7 compatibility. StringIO expects
    # unicode, but MessageToJson outputs UTF-8.
    if isinstance(json_keyset, bytes):
      json_keyset = json_keyset.decode('utf-8')
    self._io_stream.write(json_keyset)
    self._io_stream.flush()

  def write_encrypted(self, encrypted_keyset: tink_pb2.EncryptedKeyset) -> None:
    if not isinstance(encrypted_keyset, tink_pb2.EncryptedKeyset):
      raise core.TinkError('invalid encrypted keyset.')
    json_keyset = json_format.MessageToJson(encrypted_keyset)
    # TODO(b/141106504) Needed for python 2.7 compatibility. StringIO expects
    # unicode, but MessageToJson outputs UTF-8.
    if isinstance(json_keyset, bytes):
      json_keyset = json_keyset.decode('utf-8')
    self._io_stream.write(json_keyset)
    self._io_stream.flush()


class BinaryKeysetWriter(KeysetWriter):
  """Writes keysets in proto binary wire format to some storage system.

  cf. https://developers.google.com/protocol-buffers/docs/encoding
  """

  def __init__(self, binary_io_stream: BinaryIO):
    self._io_stream = binary_io_stream

  def write(self, keyset: tink_pb2.Keyset) -> None:
    if not isinstance(keyset, tink_pb2.Keyset):
      raise core.TinkError('invalid keyset.')
    self._io_stream.write(keyset.SerializeToString())
    self._io_stream.flush()

  def write_encrypted(self, encrypted_keyset: tink_pb2.EncryptedKeyset) -> None:
    if not isinstance(encrypted_keyset, tink_pb2.EncryptedKeyset):
      raise core.TinkError('invalid encrypted keyset.')
    self._io_stream.write(encrypted_keyset.SerializeToString())
    self._io_stream.flush()
