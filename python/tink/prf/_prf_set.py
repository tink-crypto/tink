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
"""This module defines the interface for PrfSet."""

import abc
from typing import Mapping


class Prf(metaclass=abc.ABCMeta):
  """An element of a pseudo random function family, selected by a key.

  The PRF interface is an abstraction for an element of a pseudo random function
  family, selected by a key. It has the following properties:

  - It is deterministic: Prf.compute(input, length) will always return the same
    output if the same key is used. Prf.compute(input, length1) will be a prefix
    of Prf.compute(input, length2) if length1 < length2 and the same key is
    used.

  - It is indistinguishable from a random function: Given the evaluation of n
    different inputs, an attacker cannot distinguish between the PRF and random
    bytes on an input different from the n that are known.

  Use cases for PRF are deterministic redaction of PII, keyed hash functions,
  creating sub IDs that do not allow joining with the original dataset without
  knowing the key. While PRFs can be used in order to prove authenticity of a
  message, using the MAC interface is recommended for that use case, as it has
  support for verification, avoiding the security problems that often happen
  during verification. It also allows for non-deterministic MAC algorithms.
  """

  @abc.abstractmethod
  def compute(self, input_data: bytes, output_length: int) -> bytes:
    """Computes the PRF selected by the underlying key.

    Args:
      input_data: The input to compute the PRF on.
      output_length: The desired length of the output in bytes. When choosing
        this parameter keep the birthday paradox in mind. If you have 2^n
        different inputs that your system has to handle set the output length to
        ceil(n/4 + 4) This corresponds to 2*n + 32 bits, meaning a
          collision will occur with a probability less than 1:2^32. When in
            doubt, request a security review.

    Returns:
      the first output_length bytes of the PRF.
    """
    raise NotImplementedError()


class PrfSet(metaclass=abc.ABCMeta):
  """A Tink Keyset can be converted into a set of PRFs using this primitive.

  Every key in the keyset corresponds to a PRF in the PrfSet. Every PRF in the
  set is given an ID, which is the same ID as the key id in the Keyset.
  """

  @abc.abstractmethod
  def primary_id(self) -> int:
    raise NotImplementedError()

  @abc.abstractmethod
  def all(self) -> Mapping[int, Prf]:
    raise NotImplementedError()

  @abc.abstractmethod
  def primary(self) -> Prf:
    raise NotImplementedError()
