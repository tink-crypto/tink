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
"""This module defines the interface for Streaming AEAD."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import abc

# Special imports
import six

from typing import BinaryIO


@six.add_metaclass(abc.ABCMeta)
class StreamingAead(object):
  """The interface for streaming authenticated encryption with associated data.

  Streaming encryption is typically used for encrypting large plaintexts such
  as large files. This interface supports a streaming interface for symmetric
  encryption with authentication. The underlying encryption modes are selected
  so that partial plaintext can be obtained fast by decrypting and
  authenticating just a part of the ciphertext.
  """

  @abc.abstractmethod
  def new_encrypting_stream(self, ciphertext_destination: BinaryIO,
                            associated_data: bytes) -> BinaryIO:
    # pyformat: disable
    """Get a new encrypting stream that writes to ciphertext_destination.

    Args:
      ciphertext_destination: A writable binary file object to which ciphertext
        will be written. It must support write(), close(), closed, and
        writable().
      associated_data: Associated data to be used by the AEAD encryption. It is
        not included in the ciphertext and must be passed in as a parameter for
        decryption.

    The ciphertext_destination's write() method is expected to present one of
    the following three behaviours in the case of a partial or failed write():
      - return a non-negative integer number of bytes written
      - return None (equivalent to returning 0)
      - raise BlockingIOError with characters_written set correctly to a
        non-negative integer (equivalent to returning that integer)
    In the case of a full write, the number of bytes written should be returned.

    The standard BufferedIOBase and RawIOBase base classes exhibit these
    behaviours and are hence supported.

    Returns:
      An encrypting file object wrapper around 'ciphertext_destination', such
      that any bytes written to the wrapper are AEAD-encrypted using
      'associated_data' as associated authenticated data.

      It supports the following:
        write()
        close()
        closed
        isatty()
        flush() (no-op)
        writable()
        readable()
        seekable()
        __enter__() and __exit__()
      Other methods, including read() and seek(), raise io.UnsupportedOperation.
      Closing the wrapper also closes the ciphertext_destination.

      The wrapper also supports the position() method, which returns the number
      of written plaintext bytes.
    Raises:
      tink.TinkError if the creation fails.
    """
    # pyformat: enable
    raise NotImplementedError()

  @abc.abstractmethod
  def new_decrypting_stream(self, ciphertext_source: BinaryIO,
                            associated_data: bytes) -> BinaryIO:
    """Get a new decrypting stream that reads from ciphertext_source.

    Args:
      ciphertext_source: A readable binary file object from which ciphertext
        will be read.
      associated_data: Associated data to be used by the AEAD decryption. It
        must match the associated_data supplied for the encryption.

    The cipertext_source's read() method is expected to return an empty bytes
    object if the stream is already at EOF. In the case where the stream is not
    at EOF yet but no data is available at the moment, it is expected to either
    return None or raise BlockingIOError.

    The standard BufferedIOBase and RawIOBase base classes exhibit these
    behaviours and are hence supported.

    Returns:
      A decrypting file object wrapper around 'ciphertext_source', such that
      any bytes read from the wrapper are AEAD-decrypted using 'associated_data'
      as associated authenticated data.

      It supports the following:
        read()
        read1()
        readinto()
        readinto1()
        readline()
        readlines()
        close()
        closed
        isatty()
        flush() (no-op)
        readable()
        writable()
        seekable()
        __enter__() and __exit__()
        __iter__() and __next__()
      Other methods, including write() and seek(), raise
      io.UnsupportedOperation.
      Closing the wrapper also closes the ciphertext_source.

      The wrapper also supports the position() method, which returns the number
      of plaintext bytes read.

    Raises:
      tink.TinkError if the creation fails.

    """
    raise NotImplementedError()
