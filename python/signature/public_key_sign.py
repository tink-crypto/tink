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

"""Interface for PublicKeySign."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import abc
# Special imports
import six


@six.add_metaclass(abc.ABCMeta)
class PublicKeySign(object):
  """Interface for public key signing.

  Digital Signatures provide functionality of signing data and verification of
  the signatures. They are represented by a pair of primitives (interfaces)
  'PublicKeySign' for signing of data, and 'PublicKeyVerify' for verification
  of signatures. Implementations of these interfaces are secure against
  adaptive chosen-message attacks. Signing data ensures the authenticity and
  the integrity of that data, but not its secrecy.
  """

  @abc.abstractmethod
  def sign(self, data: bytes) -> bytes:
    """Computes the signature for data.

    Args:
      data: bytes, the input data.
    Returns:
      The signature as bytes.
    """
    raise NotImplementedError()
