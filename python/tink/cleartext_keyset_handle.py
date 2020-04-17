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
should be restricted. Users can read encrypted keysets using
tink.read_keyset_handle.
"""
from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from tink.proto import tink_pb2
import tink


def from_keyset(keyset: tink_pb2.Keyset) -> tink.KeysetHandle:
  """Create a KeysetHandle from a keyset."""
  return tink.KeysetHandle._create(keyset)  # pylint: disable=protected-access


def read(keyset_reader: tink.KeysetReader) -> tink.KeysetHandle:
  """Create a KeysetHandle from a keyset_reader."""
  keyset = keyset_reader.read()
  return tink.KeysetHandle._create(keyset)  # pylint: disable=protected-access


def write(keyset_writer: tink.KeysetWriter,
          keyset_handle: tink.KeysetHandle) -> None:
  """Serializes and writes the keyset."""
  keyset_writer.write(keyset_handle._keyset)  # pylint: disable=protected-access
