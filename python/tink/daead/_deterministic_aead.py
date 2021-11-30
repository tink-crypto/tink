# Copyright 2019 Google LLC
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

"""This module defines the interface for Deterministic AEAD."""

import abc


class DeterministicAead(metaclass=abc.ABCMeta):
  """Interface for Deterministic Authenticated Encryption with Associated Data.

  For why this interface is desirable and some of its use cases, see for
  example https://tools.ietf.org/html/rfc5297#section-1.3.

  Warning!

  Unlike Aead, implementations of this interface are not semantically
  secure, because encrypting the same plaintex always yields the same
  ciphertext.

  Security guarantees

  Implementations of this interface provide 128-bit security level against
  multi-user attacks with up to 2^32 keys. That means if an adversary
  obtains 2^32 ciphertexts of the same message encrypted under 2^32 keys,
  they need to do 2^128 computations to obtain a single key.

  Encryption with associated data ensures authenticity (who the sender is)
  and integrity (the data has not been tampered with) of that data, but not
  its secrecy. (see https://tools.ietf.org/html/rfc5116)
  """

  @abc.abstractmethod
  def encrypt_deterministically(self, plaintext: bytes,
                                associated_data: bytes) -> bytes:
    raise NotImplementedError()

  @abc.abstractmethod
  def decrypt_deterministically(self, ciphertext: bytes,
                                associated_data: bytes) -> bytes:
    raise NotImplementedError()
