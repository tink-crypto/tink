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
"""Streaming AEAD wrapper."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import io
from typing import cast, BinaryIO, Optional, Type

from tink import core
from tink.streaming_aead import _raw_streaming_aead
from tink.streaming_aead import _rewindable_input_stream
from tink.streaming_aead import _streaming_aead


class _DecryptingStreamWrapper(io.RawIOBase):
  """A file-like object which decrypts reads from an underlying object.

  It uses a primitive set of streaming AEADs, and decrypts the stream with the
  matching key in the keyset. Closing this wrapper also closes
  ciphertext_source.
  """

  def __init__(self, primitive_set: core.PrimitiveSet,
               ciphertext_source: BinaryIO, associated_data: bytes):
    """Create a new _DecryptingStreamWrapper.

    Args:
      primitive_set: The primitive set of StreamingAead primitives.
      ciphertext_source: A readable file-like object from which ciphertext bytes
        will be read.
      associated_data: The associated data to use for decryption.
    """
    super(_DecryptingStreamWrapper, self).__init__()
    if not ciphertext_source.readable():
      raise ValueError('ciphertext_source must be readable')
    self._ciphertext_source = _rewindable_input_stream.RewindableInputStream(
        ciphertext_source)
    self._associated_data = associated_data
    self._matching_stream = None
    self._remaining_primitives = [
        entry.primitive for entry in primitive_set.raw_primitives()]
    self._attempting_stream = self._next_decrypting_stream()

  def _next_decrypting_stream(self) -> io.RawIOBase:
    """Takes the next remaining primitive and returns a decrypting stream."""
    if not self._remaining_primitives:
      raise ValueError('No primitive remaining.')
    # ciphertext_source should never be closed by any of the raw decrypting
    # streams, to be able to use it for another decrypting stream.
    # ciphertext_source will be closed in close().
    # self._ciphertext_source needs to be at the starting position.
    return self._remaining_primitives.pop(0).new_raw_decrypting_stream(
        self._ciphertext_source,
        self._associated_data,
        close_ciphertext_source=False)

  def read(self, size=-1) -> Optional[bytes]:
    """Read and return up to size bytes, where size is an int.

    Args:
      size: Maximum number of bytes to read. As a convenience, if size is
        unspecified or -1, all bytes until EOF are returned.

    Returns:
      Bytes read. An empty bytes object is returned if the stream is already at
      EOF. None is returned if no data is available at the moment.

    Raises:
      TinkError if there was a permanent error.
      ValueError if the file is closed.
    """
    if self.closed:  # pylint:disable=using-constant-test
      raise ValueError('read on closed file.')
    if size == 0:
      return bytes()
    if self._matching_stream:
      return self._matching_stream.read(size)
    # if self._matching_stream is not set, we are currently reading from
    # self._attempting_stream but no data has been read successfully yet.
    while True:
      try:
        data = self._attempting_stream.read(size)
        if data is None:
          # No data at the moment. Not clear if decryption was successful.
          # Try again with the same stream next time.
          return None
        # Any value other than None means that decryption was successful.
        # (b'' indicates that the plaintext is an empty string.)
        self._matching_stream = self._attempting_stream
        self._attempting_stream = None
        self._ciphertext_source.disable_rewind()
        return data
      except core.TinkError:
        if not self._remaining_primitives:
          raise core.TinkError(
              'No matching key found for the ciphertext in the stream')
        # Try another key.
        self._ciphertext_source.rewind()
        self._attempting_stream = self._next_decrypting_stream()

  def readinto(self, b: bytearray) -> Optional[int]:
    """Read bytes into a pre-allocated bytes-like object b."""
    data = self.read(len(b))
    if data is None:
      return None
    n = len(data)
    b[:n] = data
    return n

  def close(self) -> None:
    if self.closed:  # pylint:disable=using-constant-test
      return
    if self._matching_stream:
      self._matching_stream.close()
    if self._attempting_stream:
      self._attempting_stream.close()
    self._ciphertext_source.close()
    super(_DecryptingStreamWrapper, self).close()

  def readable(self) -> bool:
    return True


class _WrappedStreamingAead(_streaming_aead.StreamingAead):
  """Implements StreamingAead by wrapping a set of RawStreamingAead."""

  def __init__(self, primitives_set: core.PrimitiveSet):
    self._primitive_set = primitives_set

  def new_encrypting_stream(self, ciphertext_destination: BinaryIO,
                            associated_data: bytes) -> BinaryIO:
    raw = self._primitive_set.primary().primitive.new_raw_encrypting_stream(
        ciphertext_destination, associated_data)
    return cast(BinaryIO, io.BufferedWriter(raw))

  def new_decrypting_stream(self, ciphertext_source: BinaryIO,
                            associated_data: bytes) -> BinaryIO:
    raw = _DecryptingStreamWrapper(self._primitive_set, ciphertext_source,
                                   associated_data)
    return cast(BinaryIO, io.BufferedReader(raw))


class StreamingAeadWrapper(
    core.PrimitiveWrapper[_raw_streaming_aead.RawStreamingAead,
                          _streaming_aead.StreamingAead]):
  """StreamingAeadWrapper is the PrimitiveWrapper for StreamingAead."""

  def wrap(self,
           primitives_set: core.PrimitiveSet) -> _streaming_aead.StreamingAead:
    return _WrappedStreamingAead(primitives_set)

  def primitive_class(self) -> Type[_streaming_aead.StreamingAead]:
    return _streaming_aead.StreamingAead

  def input_primitive_class(
      self) -> Type[_raw_streaming_aead.RawStreamingAead]:
    return _raw_streaming_aead.RawStreamingAead
