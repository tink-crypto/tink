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
"""A file-like object that encrypts data written to it.

It writes the ciphertext to a given other file-like object, which can later be
decrypted and read using a DecryptingStream wrapper.
"""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import io
from typing import BinaryIO, Optional

from tink import core
from tink.cc.pybind import tink_bindings
from tink.streaming_aead import _file_object_adapter


@core.use_tink_errors
def _new_cc_encrypting_stream(cc_primitive, aad, destination):
  """Implemented as a separate function to ensure correct error transform."""
  return tink_bindings.new_cc_encrypting_stream(
      cc_primitive, aad, destination)


class RawEncryptingStream(io.RawIOBase):
  """A file-like object which wraps writes to an underlying file-like object.

  It encrypts any data written to it, and writes the ciphertext to the wrapped
  object.

  The close() method indicates that the message is complete, and will write a
  final ciphertext block to signify end of message.
  """

  def __init__(self, stream_aead: tink_bindings.StreamingAead,
               ciphertext_destination: BinaryIO, associated_data: bytes):
    """Create a new RawEncryptingStream.

    Args:
      stream_aead: C++ StreamingAead primitive from which a C++ EncryptingStream
        will be obtained.
      ciphertext_destination: A writable file-like object to which ciphertext
        bytes will be written.
      associated_data: The associated data to use for encryption. This must
        match the associated_data used for decryption.
    """
    super(RawEncryptingStream, self).__init__()
    if not ciphertext_destination.writable():
      raise ValueError('ciphertext_destination must be writable')
    cc_ciphertext_destination = _file_object_adapter.FileObjectAdapter(
        ciphertext_destination)
    self._cc_encrypting_stream = _new_cc_encrypting_stream(
        stream_aead, associated_data, cc_ciphertext_destination)

  @core.use_tink_errors
  def _write_to_cc_encrypting_stream(self, b: bytes) -> int:
    return self._cc_encrypting_stream.write(bytes(b))

  @core.use_tink_errors
  def _close_cc_encrypting_stream(self) -> None:
    self._cc_encrypting_stream.close()

  def readinto(self, b: bytearray) -> Optional[int]:
    raise io.UnsupportedOperation()

  def write(self, b: bytes) -> int:
    """Write the given buffer to the IO stream.

    Args:
      b: The buffer to write.
    Returns:
      The number of bytes written, which may be less than the length of b in
      bytes.
    Raises:
      TinkError: if there was a permanent error.

    """
    if self.closed:  # pylint:disable=using-constant-test
      raise ValueError('write on closed file')

    if not isinstance(b, (bytes, memoryview, bytearray)):
      raise TypeError('a bytes-like object is required, not {}'.format(
          type(b).__name__))
    written = self._write_to_cc_encrypting_stream(b)
    if written < 0 or written > len(b):
      raise core.TinkError('Incorrect number of bytes written')
    return written

  def close(self) -> None:
    """Flush and close the stream. Has no effect on a closed stream."""
    if self.closed:  # pylint:disable=using-constant-test
      return
    self.flush()
    self._close_cc_encrypting_stream()
    super(RawEncryptingStream, self).close()

  def writable(self) -> bool:
    """Return True if the stream supports writing."""
    return True
