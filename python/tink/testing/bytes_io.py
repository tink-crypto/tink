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
"""Implements a variant of BytesIO that lets you read the value after close().

This class can be used when an interface that writes to a stream and closes it
in the end need to be transformed into a function that returns a value.

An example is the implementation of normal AEAD encryption interface using
the streaming AEAD encryption interface.
"""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import errno
import io
from typing import Optional


class BytesIOWithValueAfterClose(io.BytesIO):
  """A BytesIO that lets you read the written value after close()."""

  def __init__(self, initial_bytes=None):
    self._finalvalue = None
    if initial_bytes:
      super(BytesIOWithValueAfterClose, self).__init__(initial_bytes)
    else:
      super(BytesIOWithValueAfterClose, self).__init__()

  def close(self) -> None:
    if not self.closed:
      self._value_after_close = self.getvalue()
    super(BytesIOWithValueAfterClose, self).close()

  def value_after_close(self) -> bytes:
    if not self.closed:
      raise ValueError('call to value_after_close before close()')
    return self._value_after_close


class SlowBytesIO(io.BytesIO):
  """A readable BytesIO that raised BlockingIOError on some calls to read."""

  def __init__(self, data: bytes, seekable: bool = False):
    super(SlowBytesIO, self).__init__(data)
    self._seekable = seekable
    self._state = -1

  def read(self, size: int = -1) -> bytes:
    if size > 0:
      self._state += 1
      if self._state > 10000000:
        raise AssertionError('too many read. Is there an infinite loop?')
      if self._state % 3 == 0:   # block on every third call.
        raise io.BlockingIOError(
            errno.EAGAIN,
            'write could not complete without blocking', 0)
      # read at most 5 bytes.
      return super(SlowBytesIO, self).read(min(size, 5))
    return super(SlowBytesIO, self).read(size)

  def seek(self, pos: int, whence: int = 0) -> int:
    if self._seekable:
      return super(SlowBytesIO, self).seek(pos, whence)
    raise io.UnsupportedOperation('seek')

  def seekable(self)-> bool:
    return self._seekable


class SlowReadableRawBytes(io.RawIOBase):
  """A readable io.RawIOBase stream that only sometimes returns data."""

  def __init__(self, data: bytes, seekable: bool = False):
    super(SlowReadableRawBytes, self).__init__()
    self._bytes_io = io.BytesIO(data)
    self._seekable = seekable
    self._state = -1

  def readinto(self, b: bytearray) -> Optional[int]:
    try:
      self._state += 1
      if self._state > 10000000:
        raise AssertionError('too many read. Is there an infinite loop?')
      if self._state % 3 == 0:   # return None on every third call.
        return None
      # read at most 5 bytes
      q = self._bytes_io.read(5)
      b[:len(q)] = q
      return len(q)
    except io.BlockingIOError:
      raise ValueError('io.BytesIO should not raise BlockingIOError')

  def readable(self):
    return True

  def seek(self, pos: int, whence: int = 0) -> int:
    if self._seekable:
      return self._bytes_io.seek(pos, whence)
    raise io.UnsupportedOperation('seek')

  def seekable(self)-> bool:
    return self._seekable
