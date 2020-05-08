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
"""A file-like object that encrypts data written to it.

It writes the ciphertext to a given other file-like object, which can later be
decrypted and read using a DecryptingStream wrapper.
"""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import errno
import io
from typing import Iterable, BinaryIO

from tink import core
from tink.cc.pybind import tink_bindings
from tink.util import file_object_adapter


class EncryptingStream(io.BufferedIOBase):
  """A file-like object which wraps writes to an underlying file-like object.

  It encrypts any data written to it, and writes the ciphertext to the wrapped
  object.

  The additional method position() returns the number of written plaintext
  bytes.

  Writes to an EncryptingStream may be partial - it is important to check the
  return value of write().

  The close() method indicates that the message is complete, and will write a
  final ciphertext block to signify end of message. The context manager will
  only call this close() method on a normal exit - if an exception is raised
  inside the context manager which causes it to exit early, the close() method
  will not be called, and the ciphertext will not be complete.
  """

  def __init__(self, stream_aead, ciphertext_destination: BinaryIO,
               associated_data: bytes):
    """Create a new EncryptingStream.

    Args:
      stream_aead: C++ StreamingAead primitive from which a C++ EncryptingStream
        will be obtained.
      ciphertext_destination: A writable file-like object to which ciphertext
        bytes will be written.
      associated_data: The associated data to use for encryption. This must
        match the associated_data used for decryption.
    """
    super(EncryptingStream, self).__init__()
    self._closed = False
    self._bytes_written = 0

    # Create FileObjectAdapter
    if not ciphertext_destination.writable():
      raise ValueError('ciphertext_destination must be writable')
    cc_ciphertext_destination = file_object_adapter.FileObjectAdapter(
        ciphertext_destination)
    # Get OutputStreamAdapter of C++ EncryptingStream
    self._output_stream_adapter = self._get_output_stream_adapter(
        stream_aead, associated_data, cc_ciphertext_destination)

  @staticmethod
  @core.use_tink_errors
  def _get_output_stream_adapter(cc_primitive, aad, destination):
    """Implemented as a separate method to ensure correct error transform."""
    return tink_bindings.new_cc_encrypting_stream(
        cc_primitive, aad, destination)

  @core.use_tink_errors
  def write(self, b: bytes) -> int:
    """Write the given buffer to the stream.

    May use multiple calls to the underlying file object's write() method.

    Returns:
      The number of bytes written, which will always be the length of b in
      bytes.

    Raises:
      BlockingIOError: if the write could not be fully completed, with
        characters_written set to the number of bytes successfully written.
      TinkError: if there was a permanent error.

    Args:
      b: The buffer to write.
    """
    self._check_not_closed()

    if not isinstance(b, (bytes, memoryview, bytearray)):
      raise TypeError('a bytes-like object is required, not {}'.format(
          type(b).__name__))

    # One call to OutputStreamAdapter.write() may call next() multiple times
    # on the C++ EncryptingStream, but will perform a partial write if there is
    # a temporary write error. Permanent write errors will bubble up as
    # exceptions.
    written = self._output_stream_adapter.write(b)
    if written < 0:
      raise core.TinkError('Number of written bytes was negative')

    self._bytes_written += written

    if written < len(b):
      raise io.BlockingIOError(errno.EAGAIN,
                               'Write could not complete without blocking.',
                               written)
    elif written > len(b):
      raise core.TinkError(
          'Number of written bytes was greater than length of bytes given')

    return written

  def writelines(self, lines: Iterable[bytes]) -> None:
    """Write a list of lines to the stream.

    Line separators are not added, so it is usual for each of the lines
    provided to have a line separator at the end.

    Args:
      lines: An iterable of buffers to write to the stream.
    """
    self._check_not_closed()
    for line in lines:
      self.write(line)

  ### Internal ###

  # TODO(b/141344377) Use parent class _checkClosed() instead
  def _check_not_closed(self, msg=None):
    """Internal: raise a ValueError if file is closed."""
    if self.closed:
      raise ValueError('I/O operation on closed file.' if msg is None else msg)

  ### Positioning ###

  def position(self) -> int:
    """Returns total number of written plaintext bytes."""
    return self._bytes_written

  ### Flush and close ###

  def flush(self) -> None:
    """Flush write buffers.

    This method has no effect.
    """
    self._check_not_closed()
    return

  @core.use_tink_errors
  def close(self) -> None:
    """Flush and close the stream.

    This has no effect on a closed stream.
    """
    if self.closed:
      return
    self.flush()
    self._output_stream_adapter.close()
    self._closed = True

  def __del__(self):
    """Destructor.  Calls flush()."""
    try:
      # We deliberately don't close the file here, since we don't know if the
      # user was really done writing or if there was an error.
      self.flush()
    except Exception:  # pylint: disable=broad-except
      pass

  ### Inquiries ###

  def writable(self) -> bool:
    """Indicates whether object was opened for writing.

    Returns:
      Whether object was opened for writing.

    If False, write() and truncate() will raise UnsupportedOperation.
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

  def __exit__(self, exc_type, exc_val, exc_tb) -> None:
    """Context management protocol.  Calls close() if there was no exception."""
    # Calling close() signifies that the message is complete - we should not
    # do this if there was an exception.
    # Instead, we let the destructors be called, which should lead to sufficient
    # cleanup on the other end, and if ciphertext_destination calls close() in
    # __del__ (as IOBase does) then the underlying file descriptor should also
    # be closed eventually.
    if exc_type is None:
      self.close()

  ### Iterator ###
  def __iter__(self):
    """Iterator API."""
    raise io.UnsupportedOperation('Cannot iterate an EncryptingStream')

  def __next__(self):
    """Iterator API."""
    raise io.UnsupportedOperation('Cannot iterate an EncryptingStream')
