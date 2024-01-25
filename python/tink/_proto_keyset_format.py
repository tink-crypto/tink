# Copyright 2023 Google LLC
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
"""This module defines the Tink Proto Keyset serialization Format."""

import io

from tink import _insecure_keyset_handle
from tink import _keyset_handle
from tink import _keyset_reader
from tink import _keyset_writer
from tink import aead
from tink import core


def parse(
    serialized_keyset: bytes, token: core.KeyAccess
) -> _keyset_handle.KeysetHandle:
  """Parses a Tink keyset. Access is restricted with a token."""
  keyset = _keyset_reader.BinaryKeysetReader(serialized_keyset).read()
  return _insecure_keyset_handle.from_proto_keyset(keyset, token)


def serialize(
    keyset_handle: _keyset_handle.KeysetHandle, token: core.KeyAccess
) -> bytes:
  """Serializes a Tink keyset. Access is restricted with a token."""
  output_stream = io.BytesIO()
  writer = _keyset_writer.BinaryKeysetWriter(output_stream)
  writer.write(_insecure_keyset_handle.to_proto_keyset(keyset_handle, token))
  return output_stream.getvalue()


def parse_without_secret(
    serialized_keyset: bytes,
) -> _keyset_handle.KeysetHandle:
  """Parses a Tink keyset. The keyset must not contain any secret data."""
  return _keyset_handle.read_no_secret_keyset_handle(
      _keyset_reader.BinaryKeysetReader(serialized_keyset)
  )


def serialize_without_secret(
    keyset_handle: _keyset_handle.KeysetHandle,
) -> bytes:
  """Serializes a Tink keyset. The keyset must not contain any secret data."""
  output_stream = io.BytesIO()
  writer = _keyset_writer.BinaryKeysetWriter(output_stream)
  keyset_handle.write_no_secret(writer)
  return output_stream.getvalue()


def parse_encrypted(
    serialized_encrypted_keyset: bytes,
    keyset_encryption_aead: aead.Aead,
    associated_data: bytes,
) -> _keyset_handle.KeysetHandle:
  """Parses an encrypted Tink keyset."""
  return _keyset_handle.read_keyset_handle_with_associated_data(
      _keyset_reader.BinaryKeysetReader(serialized_encrypted_keyset),
      keyset_encryption_aead,
      associated_data,
  )


def serialize_encrypted(
    keyset_handle: _keyset_handle.KeysetHandle,
    keyset_encryption_aead: aead.Aead,
    associated_data: bytes,
) -> bytes:
  """Serializes an encrypted Tink keyset."""
  output_stream = io.BytesIO()
  writer = _keyset_writer.BinaryKeysetWriter(output_stream)
  keyset_handle.write_with_associated_data(
      writer,
      keyset_encryption_aead,
      associated_data,
  )
  return output_stream.getvalue()
