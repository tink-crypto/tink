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
"""A Raw Input stream wrapper that supports rewinding."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import io
from typing import Optional, BinaryIO


class RewindableInputStream(io.RawIOBase):
  """Implements a readable io.RawIOBase wrapper that supports rewinding.

  The wrapped input_stream can either be a io.RawIOBase or io.BufferedIOBase.
  """

  def __init__(self, input_stream: BinaryIO):
    super(RewindableInputStream, self).__init__()
    if not input_stream.readable():
      raise ValueError('input_stream must be readable')
    self._input_stream = input_stream
    self._buffer = bytearray()
    self._pos = 0
    self._rewindable = True

  def read(self, size: int = -1) -> Optional[bytes]:
    """Read and return up to size bytes when size >= 0.

    If input_stream.read returns None to indicate "No data at the moment", this
    function may return None as well. But it will eventually return
    some data, or return b'' if EOF is reached.

    Args:
      size: Maximum number of bytes to be returned, if >= 0. If size is smaller
        than 0 or None, return the whole content of the file.
    Returns:
      bytes read. b'' is returned on EOF, and None if there is currently
      no data available, but EOF is not reached yet.
    """
    if size is None or size < 0:
      return self.readall()  # implemented in io.RawIOBase
    if self._pos < len(self._buffer):
      # buffer has some data left. Return up to 'size' bytes from the buffer
      new_pos = min(len(self._buffer), self._pos + size)
      b = self._buffer[self._pos:new_pos]
      self._pos = new_pos
      return bytes(b)
    # no data left in buffer
    if not self._rewindable and self._buffer:
      # buffer is not needed anymore
      self._buffer = bytearray()
      self._pos = 0
    try:
      data = self._input_stream.read(size)
    except BlockingIOError:
      # self._input_stream is a BufferedIOBase and has currently no data
      return None
    if data is None:
      # self._input_stream is a RawIOBase and has currently no data
      return None
    if self._rewindable:
      self._buffer.extend(data)
      self._pos += len(data)
    return data

  def rewind(self) -> None:
    if not self._rewindable:
      raise ValueError('rewind is disabled')
    self._pos = 0

  def disable_rewind(self) -> None:
    self._rewindable = False

  def readable(self) -> bool:
    return True

  def close(self) -> None:
    """Close the stream and the wrapped input_stream."""
    if self.closed:  # pylint:disable=using-constant-test
      return
    self._input_stream.close()
    super(RewindableInputStream, self).close()
