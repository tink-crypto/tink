# Copyright 2019 Google LLC.
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

"""This module defines the interface for AEAD."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import abc

# Special imports
import six


@six.add_metaclass(abc.ABCMeta)
class Aead(object):
  """The interface for authenticated encryption with associated data.

  Implementations of this interface are secure against adaptive
  chosen ciphertext attacks.  Encryption with associated data ensures
  authenticity and integrity of that data, but not its secrecy.
  (see RFC 5116, https://tools.ietf.org/html/rfc5116)
  """

  @abc.abstractmethod
  def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
    """Encrypts plaintext with associated_data.

    The ciphertext allows for checking authenticity and integrity of the
    associated data, but does not guarantee its secrecy.

    Args:
      plaintext: bytes. The data to be encrypted.
      associated_data: bytes. The associated data, that will be authenticated.
    Returns:
      the resulting ciphertext as bytes.
    Raises:
      tink.TinkError if the encryption fails.
    """
    raise NotImplementedError()

  @abc.abstractmethod
  def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes:
    """Decrypts ciphertext with associated_data.

    The decryption verifies the authenticity and integrity of the associated
    data, but there are no guarantees with respect to secrecy of that data.

    Args:
      ciphertext: bytes. The data to be decrypted.
      associated_data: bytes. The associated data.
    Returns:
      the resulting plaintext as bytes.
    Raises:
      tink.TinkError if the decryption fails.
    """
    raise NotImplementedError()
