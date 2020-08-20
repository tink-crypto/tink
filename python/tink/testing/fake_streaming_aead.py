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


class _FakeDecryptingStream(io.RawIOBase):
  """A fake implementation of a decyrpting stream."""

  def __init__(self, name: Text,
               ciphertext_source: BinaryIO,
               associated_data: bytes,
               close_ciphertext_source: bool):
    super(_FakeDecryptingStream, self).__init__()
    self._name = name
    self._ciphertext_source = ciphertext_source
    self._associated_data = associated_data
    self._close_ciphertext_source = close_ciphertext_source
    self._error = False
    self._data = bytearray()
    self._bytes_io = None

  def read(self, size: int = -1) -> Optional[bytes]:
    if self._error:
      raise self._error
    if not self._bytes_io:
      # read to EOF, and don't stop when None is returned.
      while True:
        try:
          d = self._ciphertext_source.read()
          if d is None:
            return None
        except BlockingIOError:
          # There is currently no data available. This error may be raised by a
          # BufferedIOBase source. For RawIOBase, we have to return None in this
          # case.
          return None
        if not d:
          # d == b'', which means EOF
          break
        self._data.extend(d)
      data = bytes(self._data).split(b'|')
      if (len(data) < 3 or data[1] != self._associated_data or
          data[0] != self._name.encode()):
        self._error = core.TinkError('error occured.')
        raise self._error
      self._bytes_io = io.BytesIO(data[2])
    return self._bytes_io.read(size)

  def readinto(self, b: bytearray) -> Optional[int]:
    data = self.read(len(b))
    if data is None:
      return None
    n = len(data)
    b[:n] = data
    return n

  def readable(self):
    return True

  def close(self):
    if not self.closed and self._close_ciphertext_source:
      self._ciphertext_source.close()
    super(_FakeDecryptingStream, self).close()


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
    return _FakeDecryptingStream(
        self._name, ciphertext_source, associated_data, close_ciphertext_source)
