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
"""CleartextKeysetHandle module.

WARNING

Reading or writing cleartext keysets is a bad practice, usage of this API
should be restricted. Users can read encrypted keysets using KeysetHandle.read.
"""
from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from proto import tink_pb2
from tink.core import keyset_handle as handle
from tink.core import keyset_reader as reader
from tink.core import keyset_writer as writer


def from_keyset(keyset: tink_pb2.Keyset) -> handle.KeysetHandle:
  """Create a KeysetHandle from a keyset."""
  return handle.KeysetHandle._create(keyset)  # pylint: disable=protected-access


def read(keyset_reader: reader.KeysetReader) -> handle.KeysetHandle:
  """Create a KeysetHandle from a keyset_reader."""
  keyset = keyset_reader.read()
  return handle.KeysetHandle._create(keyset)  # pylint: disable=protected-access


def write(keyset_writer: writer.KeysetWriter,
          keyset_handle: handle.KeysetHandle) -> None:
  """Serializes and writes the keyset."""
  keyset_writer.write(keyset_handle._keyset)  # pylint: disable=protected-access


# DEPRECATED. Use static functions instead.
class CleartextKeysetHandle(handle.KeysetHandle):
  """CleartextKeysetHandle creates KeysetHandle from a Tink Keyset."""

  def __new__(cls, keyset: tink_pb2.Keyset):
    return cls._create(keyset)

  @classmethod
  def read(cls,
           keyset_reader: reader.KeysetReader) -> handle.KeysetHandle:
    """Create a KeysetHandle from a keyset read with keyset_reader."""
    keyset = keyset_reader.read()
    return cls._create(keyset)

  def write(self, keyset_writer: writer.KeysetWriter) -> None:
    """Serializes and writes the keyset."""
    keyset_writer.write(self._keyset)
