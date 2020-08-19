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
"""This module implements streaming_aead helper functions for testing."""

import io
from typing import Optional, Text, BinaryIO

from tink import core
from tink.streaming_aead import _raw_streaming_aead


class _ReadableRawBytes(io.RawIOBase):
  """A readable RawIOBase implementation that also closes another file."""

  def __init__(self, data: bytes, also_close: Optional[BinaryIO] = None):
    super(_ReadableRawBytes, self).__init__()
    self._bytes_io = io.BytesIO(data)
    self._also_close = also_close

  def readinto(self, b: bytearray) -> Optional[int]:
    try:
      return self._bytes_io.readinto1(b)
    except BlockingIOError as b:
      if not b.characters_written:
        # No data at the moment
        return None
      else:
        return b.characters_written

  def readable(self):
    return True

  def close(self):
    if not self.closed and self._also_close:
      self._also_close.close()
    super(_ReadableRawBytes, self).close()


class _AlwaysFailingDecryptingStream(io.RawIOBase):
  """A readable RawIOBase that raises a TinkError on read and readinto."""

  def __init__(self, also_close: Optional[BinaryIO] = None):
    super(_AlwaysFailingDecryptingStream, self).__init__()
    self._also_close = also_close

  def readinto(self, b: bytearray) -> Optional[int]:
    raise core.TinkError('decryption failed')

  def readable(self) -> bool:
    return True

  def close(self):
    if not self.closed and self._also_close:
      self._also_close.close()
    super(_AlwaysFailingDecryptingStream, self).close()


class _WritableRawBytes(io.RawIOBase):
  """A writeable RawIOBase implementation."""

  def __init__(self, destination: BinaryIO):
    super(_WritableRawBytes, self).__init__()
    self._destination = destination  # can be RawIOBase or BufferedIOBase.

  def write(self, b: bytearray) -> Optional[int]:
    try:
      return self._destination.write(b)
    except BlockingIOError as b:
      if not b.characters_written:
        # No data could be written
        return None
      else:
        return b.characters_written

  def writable(self):
    return True

  def close(self):
    if not self.closed:
      self._destination.close()
    super(_WritableRawBytes, self).close()


class FakeRawStreamingAead(_raw_streaming_aead.RawStreamingAead):
  """A fake Raw Streaming AEAD implementation.

  It "encrypts" the ciphertext by writing name|associated_data|plaintext
  to the destination. "Decryption" returns a readable stream that output
  plaintext if name and associated_data match, and raised a TinkError
  on read otherwise.
  """

  def __init__(self, name: Text = 'FakeStreamingAead'):
    self._name = name

  def new_raw_encrypting_stream(self, ciphertext_destination: BinaryIO,
                                associated_data: bytes) -> io.RawIOBase:
    # the ciphertext has the format: name|associated_data|plaintext
    ciphertext_destination.write(self._name.encode())
    ciphertext_destination.write(b'|')
    ciphertext_destination.write(associated_data)
    ciphertext_destination.write(b'|')
    return _WritableRawBytes(ciphertext_destination)

  def new_raw_decrypting_stream(self, ciphertext_source: BinaryIO,
                                associated_data: bytes,
                                close_ciphertext_source: bool) -> io.RawIOBase:
    data = ciphertext_source.read().split(b'|')
    if not close_ciphertext_source:
      ciphertext_source = None
    if (len(data) < 3 or data[1] != associated_data or
        data[0] != self._name.encode()):
      return _AlwaysFailingDecryptingStream(ciphertext_source)
    else:
      return _ReadableRawBytes(data[2], ciphertext_source)
