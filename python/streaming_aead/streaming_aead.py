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
from __future__ import google_type_annotations
from __future__ import print_function

import abc
from typing import BinaryIO


class StreamingAead(object):
  """The interface for streaming authenticated encryption with associated data.

  Streaming encryption is typically used for encrypting large plaintexts such
  as large files. This interface supports a streaming interface for symmetric
  encryption with authentication. The underlying encryption modes are selected
  so that partial plaintext can be obtained fast by decrypting and
  authenticating just a part of the ciphertext.
  """

  __metaclass__ = abc.ABCMeta

  @abc.abstractmethod
  def new_encrypting_stream(self, ciphertext_destination: BinaryIO,
                            associated_data: bytes) -> BinaryIO:
    """Get a new encrypting stream that writes to ciphertext_destination.

    Args:
      ciphertext_destination: A writable binary file object to which ciphertext
        will be written. It must support write(), close(), closed, and
        writable().
      associated_data: Associated data to be used by the AEAD encryption. It is
        not included in the ciphertext and must be passed in as a parameter for
        decryption.

    Returns:
      An encrypting file object wrapper around 'ciphertext_destination', such
      that any bytes written to the wrapper are AEAD-encrypted using
      'associated_data' as associated authenticated data.

      It supports the following:
        write()
        close()
        closed
        tell()
        isatty()
        flush() (no-op)
        writable()
        readable()
        seekable()
        __enter__() and __exit__()
      Other methods, including read() and seek(), raise io.UnsupportedOperation.
      Closing the wrapper also closes the ciphertext_destination.

    Raises:
      tink.TinkError if the creation fails.
    """
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
        readall()
        close()
        closed
        tell()
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

    Raises:
      tink.TinkError if the creation fails.

    """
    raise NotImplementedError()
