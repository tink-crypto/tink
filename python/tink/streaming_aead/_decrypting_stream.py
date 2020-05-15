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
"""A file-like object that decrypts the data it reads.

It reads the ciphertext from a given other file-like object, and decrypts it.
"""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import errno
import io
from typing import BinaryIO

from tink import core
from tink.cc.pybind import tink_bindings
from tink.util import file_object_adapter


class DecryptingStream(io.BufferedIOBase):
  """A file-like object which decrypts reads from an underlying object.

  It reads the ciphertext from the wrapped file-like object, and decrypts it.

  The additional method position() returns the number of read plaintext bytes.

  Closing this wrapper also closes the underlying object.
  """

  def __init__(self, stream_aead, ciphertext_source: BinaryIO,
               associated_data: bytes):
    """Create a new DecryptingStream.

    Args:
      stream_aead: C++ StreamingAead primitive from which a C++ DecryptingStream
        will be obtained.
      ciphertext_source: A readable file-like object from which ciphertext bytes
        will be read.
      associated_data: The associated data to use for decryption.
    """
    super(DecryptingStream, self).__init__()
    self._closed = False
    self._bytes_read = 0
    self._ciphertext_source = ciphertext_source

    # Create FileObjectAdapter
    if not ciphertext_source.readable():
      raise ValueError('ciphertext_source must be readable')
    cc_ciphertext_source = file_object_adapter.FileObjectAdapter(
        ciphertext_source)
    # Get InputStreamAdapter of C++ DecryptingStream
    self._input_stream_adapter = self._get_input_stream_adapter(
        stream_aead, associated_data, cc_ciphertext_source)

  @staticmethod
  @core.use_tink_errors
  def _get_input_stream_adapter(cc_primitive, aad, source):
    """Implemented as a separate method to ensure correct error transform."""
    return tink_bindings.new_cc_decrypting_stream(
        cc_primitive, aad, source)

  ### Reading ###

  def read(self, size: int = -1) -> bytes:
    """Read and return up to size bytes.

    Multiple reads may be issued to the underlying object.

    Args:
      size: Maximum number of bytes to read. If the argument is omitted, None,
        or negative, data is read and returned until EOF or if the read call
        would block in non-blocking mode.

    Returns:
      Bytes read. An empty bytes object is returned if the stream is already at
      EOF.

    Raises:
      BlockingIOError if no data is available at the moment.
      TinkError if there was a permanent error.
    """
    return self._read(size, read1=False)

  def read1(self, size: int = -1) -> bytes:
    """Read and return up to size bytes.

    At most one read will be issued to the underlying object.

    Args:
      size: Maximum number of bytes to read. If the argument is omitted, None,
        or negative, an arbitrary number of bytes are returned.

    Returns:
      Bytes read. An empty bytes object is returned if the stream is already at
      EOF.

    Raises:
      BlockingIOError if no data is available at the moment.
      TinkError if there was a permanent error.
    """
    return self._read(size, read1=True)

  def readinto(self, b: bytearray) -> int:
    """Read bytes into a pre-allocated bytes-like object b.

    Multiple reads may be issued to the underlying object.

    Args:
      b: Bytes-like object to which data will be read.

    Returns:
      Number of bytes read. If 0 is returned it means EOF is reached.

    Raises:
      BlockingIOError if no data is available at the moment.
      TinkError if there was a permanent error.
    """
    return self._readinto(b, read1=False)

  def readinto1(self, b: bytearray) -> int:
    """Read bytes into a pre-allocated bytes-like object b.

    At most one read will be issued to the underlying object.

    Args:
      b: Bytes-like object to which data will be read.

    Returns:
      Number of bytes read. If 0 is returned it means EOF is reached.

    Raises:
      BlockingIOError if no data is available at the moment.
      TinkError if there was a permanent error.
    """
    return self._readinto(b, read1=True)

  def _read(self, size: int, read1: bool) -> bytes:
    self._check_not_closed()

    if size is None:
      size = -1

    try:
      if read1:
        data = self._read1_with_tink_error(size)
      else:
        data = self._read_with_tink_error(size)

      if not data:
        raise io.BlockingIOError(errno.EAGAIN,
                                 'No data available at the moment.')
      else:
        self._bytes_read += len(data)
        return data
    except core.TinkError as e:
      # We are checking if the exception was raised because of C++
      # OUT_OF_RANGE status, which signals EOF.
      wrapped_e = e.args[0]
      if (isinstance(wrapped_e, tink_bindings.StatusNotOk) and
          wrapped_e.args[0] == tink_bindings.ErrorCode.OUT_OF_RANGE):
        return b''
      else:
        raise e

  # TODO(b/141344377) use the implementation in parent class
  def _readinto(self, b: bytearray, read1: bool) -> int:
    data = self._read(len(b), read1)
    n = len(data)
    b[:n] = data
    return n

  @core.use_tink_errors
  def _read_with_tink_error(self, size: int) -> bytes:
    """Implemented as a separate method to ensure correct error transform."""
    return self._input_stream_adapter.read(size)

  @core.use_tink_errors
  def _read1_with_tink_error(self, size: int) -> bytes:
    """Implemented as a separate method to ensure correct error transform."""
    return self._input_stream_adapter.read1(size)

  ### Internal ###

  # TODO(b/141344377) use parent class _checkClosed() instead
  def _check_not_closed(self, msg=None):
    """Internal: raise a ValueError if file is closed."""
    if self.closed:
      raise ValueError('I/O operation on closed file.' if msg is None else msg)

  ### Positioning ###

  def position(self) -> int:
    """Returns total number of read plaintext bytes."""
    return self._bytes_read

  ### Flush and close ###

  def flush(self) -> None:
    """This has no effect because the stream is read-only."""
    self._check_not_closed()

  def close(self) -> None:
    """Close the stream.

    This has no effect on a closed stream.
    """
    if self.closed:
      return
    self._ciphertext_source.close()
    self._closed = True

  ### Inquiries ###

  def readable(self) -> bool:
    """Indicates whether object was opened for reading.

    Returns:
      Whether object was opened for reading.

    If False, read() will raise UnsupportedOperation.
    """
    return True

  @property
  def closed(self) -> bool:
    """Indicates if the file has been closed.

    Returns:
      True if and only if the file has been closed.

    For backwards compatibility, this is a property, not a predicate.
    """
    return self._closed
