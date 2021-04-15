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
"""A file-like object that decrypts the data it reads.

It reads the ciphertext from a given other file-like object, and decrypts it.
"""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import io
from typing import BinaryIO

from tink import core
from tink.cc.pybind import tink_bindings
from tink.streaming_aead import _file_object_adapter


class RawDecryptingStream(io.RawIOBase):
  """A file-like object which decrypts reads from an underlying object.

  It reads the ciphertext from the wrapped file-like object, and decrypts it.
  """

  def __init__(self, stream_aead: tink_bindings.StreamingAead,
               ciphertext_source: BinaryIO, associated_data: bytes, *,
               close_ciphertext_source: bool):
    """Create a new RawDecryptingStream.

    Args:
      stream_aead: C++ StreamingAead primitive from which a C++ DecryptingStream
        will be obtained.
      ciphertext_source: A readable file-like object from which ciphertext bytes
        will be read.
      associated_data: The associated data to use for decryption.
      close_ciphertext_source: Whether ciphertext_source should be closed when
        close() is called.
    """
    super(RawDecryptingStream, self).__init__()
    self._ciphertext_source = ciphertext_source
    self._close_ciphertext_source = close_ciphertext_source
    if not ciphertext_source.readable():
      raise ValueError('ciphertext_source must be readable')
    cc_ciphertext_source = _file_object_adapter.FileObjectAdapter(
        ciphertext_source)
    self._input_stream_adapter = self._get_input_stream_adapter(
        stream_aead, associated_data, cc_ciphertext_source)

  @staticmethod
  @core.use_tink_errors
  def _get_input_stream_adapter(cc_primitive, aad, source):
    """Implemented as a separate method to ensure correct error transform."""
    return tink_bindings.new_cc_decrypting_stream(
        cc_primitive, aad, source)

  @core.use_tink_errors
  def _read_from_input_stream_adapter(self, size: int) -> bytes:
    """Implemented as a separate method to ensure correct error transform."""
    return self._input_stream_adapter.read(size)

  def read(self, size=-1) -> bytes:
    """Read and return up to size bytes, where size is an int.

    It blocks until at least one byte can be returned.

    Args:
      size: Maximum number of bytes to read. As a convenience, if size is
      unspecified or -1, all bytes until EOF are returned.

    Returns:
      Bytes read. If b'' is returned and size was not 0, this indicates EOF.

    Raises:
      TinkError if there was a permanent error.
    """
    if self.closed:  # pylint:disable=using-constant-test
      raise ValueError('read on closed file.')
    if size is None:
      size = -1
    if size < 0:
      return self.readall()
    try:
      # _input_stream_adapter may return an empty string when there is currently
      # no data is available. In Python (in blocking mode), read is expected to
      # block until some data is available.
      # https://docs.python.org/3/library/io.html also mentions a
      # non-blocking mode, but according to https://bugs.python.org/issue13322
      # that mode is not properly implemented and not really used.
      while True:
        data = self._read_from_input_stream_adapter(size)
        if data:
          return data
    except core.TinkError as e:
      # We are checking if the exception was raised because of C++
      # OUT_OF_RANGE status, which signals EOF.
      wrapped_e = e.args[0]
      if (isinstance(wrapped_e, tink_bindings.StatusNotOk) and
          (wrapped_e.status.error_code() ==
           tink_bindings.ErrorCode.OUT_OF_RANGE)):
        return b''
      else:
        raise e

  def readinto(self, b: bytearray) -> int:
    """Read bytes into a pre-allocated bytes-like object b.

    Args:
      b: Bytes-like object to which data will be read.

    Returns:
      Number of bytes read. It returns 0 if EOF is reached, and None if no data
      is available at the moment.

    Raises:
      TinkError if there was a permanent error.
    """
    data = self.read(len(b))
    n = len(data)
    b[:n] = data
    return n

  def close(self) -> None:
    """Close the stream. Has no effect on a closed stream."""
    if self.closed:  # pylint:disable=using-constant-test
      return
    if self._close_ciphertext_source:
      self._ciphertext_source.close()
    super(RawDecryptingStream, self).close()

  def readable(self) -> bool:
    """Return True if the stream can be read from."""
    return True

  def write(self, b: bytes) -> int:
    raise io.UnsupportedOperation()
