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

"""This module defines the interface for HybridDecrypt."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import abc

# Special imports
import six


@six.add_metaclass(abc.ABCMeta)
class HybridDecrypt(object):
  """The interface for hybrid decryption.

  Implementations of this interface are secure against adaptive
  chosen ciphertext attacks.  In addition to 'plaintext' the
  encryption takes an extra parameter 'context_info', which usually
  is public data implicit from the context, but should be bound to
  the resulting ciphertext: upon decryption the ciphertext allows for
  checking the integrity of 'context_info' (but there are no
  guarantees wrt. to secrecy or authenticity of 'context_info').

  WARNING: hybrid encryption does not provide authenticity, that is the
  recipient of an encrypted message does not know the identity of the sender.
  Similar to general public-key encryption schemes the security goal of
  hybrid encryption is to provide privacy only. In other words, hybrid
  encryption is secure if and only if the recipient can accept anonymous
  messages or can rely on other mechanisms to authenticate the sender.

  'context_info' can be empty or null, but to ensure the correct
  decryption of the resulting ciphertext the same value must be
  provided for decryption operation (cf. HybridDecrypt-interface).

  A concrete instantiation of this interface can implement the
  binding of 'context_info' to the ciphertext in various ways, for
  example:

  - use 'context_info' as "associated data"-input for the employed
    AEAD symmetric encryption (cf. https://tools.ietf.org/html/rfc5116).
  - use 'context_info' as "CtxInfo"-input for HKDF (if the implementation uses
    HKDF as key derivation function, cf. https://tools.ietf.org/html/rfc5869).
  """

  @abc.abstractmethod
  def decrypt(self, ciphertext: bytes, context_info: bytes) -> bytes:
    """Decrypts ciphertext verifying the integrity of context_info."""
    raise NotImplementedError()
