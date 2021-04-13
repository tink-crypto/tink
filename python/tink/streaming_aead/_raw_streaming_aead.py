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
"""This module defines the 'raw' interface for Streaming AEAD."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import abc
import io
from typing import BinaryIO

# Special imports
import six


@six.add_metaclass(abc.ABCMeta)
class RawStreamingAead(object):
  """Raw interface for streaming authenticated encryption with associated data.

  Streaming encryption is typically used for encrypting large plaintexts such
  as large files. This interface supports a streaming interface for symmetric
  encryption with authentication. The underlying encryption modes are selected
  so that partial plaintext can be obtained fast by decrypting and
  authenticating just a part of the ciphertext.

  This is the 'raw' interface implemented by key managers, based on
  io.RawIOBase. Users usually don't use this directly. Instead, they should use
  streaming_aead.StreamingAead, generated from a keyset_handle.
  """

  @abc.abstractmethod
  def new_raw_encrypting_stream(self, ciphertext_destination: BinaryIO,
                                associated_data: bytes) -> io.RawIOBase:
    """Returns a raw encrypting stream that writes to ciphertext_destination.

    The returned stream implements a writable io.RawIOBase interface. Users
    usually don't use this directly, they should use
    streaming_aead.StreamingAead instead.

    The ciphertext_destination's write() method is expected to present one of
    the following three behaviours in the case of a partial or failed write():
      - return a non-negative integer number of bytes written
      - return None (equivalent to returning 0)
      - raise BlockingIOError with characters_written set correctly to a
        non-negative integer (equivalent to returning that integer)
    In the case of a full write, the number of bytes written should be returned.
    The standard io.BufferedIOBase and io.RawIOBase base classes exhibit these
    behaviours and are hence supported.

    Args:
      ciphertext_destination: A writable binary file object to which ciphertext
        will be written. It must support write(), close(), closed, and
        writable().
      associated_data: Associated data to be used by the AEAD encryption. It is
        not included in the ciphertext and must be passed in as a parameter for
        decryption.

    Returns:
      A writable implementation of the io.RawIOBase interface that wraps around
      'ciphertext_destination', such that any bytes written to the wrapper are
      AEAD-encrypted using 'associated_data' as associated authenticated data.
      Closing this wrapper also closes the ciphertext_source.
    Raises:
      tink.TinkError if the creation fails.
    """
    raise NotImplementedError()

  @abc.abstractmethod
  def new_raw_decrypting_stream(
      self,
      ciphertext_source: BinaryIO,
      associated_data: bytes,
      close_ciphertext_source: bool) -> io.RawIOBase:
    """Returns a raw decrypting stream that reads from ciphertext_source.

    The returned stream implements a readable io.RawIOBase interface. Users
    usually don't use this directly, they should use
    streaming_aead.StreamingAead instead.

    The cipertext_source's read() method is expected to return an empty bytes
    object if the stream is already at EOF. In the case where the stream is not
    at EOF yet but no data is available at the moment, it is expected to either
    block until data is available, return None or raise a BlockingIOError.
    The standard io.BufferedIOBase and io.RawIOBase base classes exhibit these
    behaviours and are hence supported.

    Args:
      ciphertext_source: A readable binary file object from which ciphertext
        will be read.
      associated_data: Associated data to be used by the AEAD decryption. It
        must match the associated_data supplied for the encryption.
      close_ciphertext_source: Whether ciphertext_source should be closed when
      close() is called.

    Returns:
      A readable implementation of the io.RawIOBase interface that wraps around
      'ciphertext_source', such that any bytes read from the wrapper are
      AEAD-decrypted using 'associated_data' as associated authenticated data.
    Raises:
      tink.TinkError if the creation fails.
    """
    raise NotImplementedError()
