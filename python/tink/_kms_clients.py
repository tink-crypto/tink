# Copyright 2023 Google LLC
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

"""This module provides a global list of KMS Clients."""

import abc
from typing import List
import warnings

from tink.aead import _aead
from tink.core import _tink_error


class KmsClient(metaclass=abc.ABCMeta):

  @abc.abstractmethod
  def does_support(self, key_uri: str) -> bool:
    raise NotImplementedError()

  @abc.abstractmethod
  def get_aead(self, key_uri: str) -> _aead.Aead:
    raise NotImplementedError()


_kms_clients: List[KmsClient] = []


# Deprecated. It is preferable to not register KMS clients. Instead, get the
# KMS AEAD with kms_aead = client.get_aead(key_uri) and then use it to encrypt
# a keyset with KeysetHandle.write, or to create an envelope AEAD using
# aead.KmsEnvelopeAead.
def register_kms_client(client: KmsClient) -> None:
  """Adds a KMS client to a global list."""
  warnings.warn(
      'The "register_kms_client" function is deprecated.',
      DeprecationWarning,
      2,
  )
  _kms_clients.append(client)


# Deprecated. It is preferable to not register KMS clients.
def kms_client_from_uri(key_uri: str) -> KmsClient:
  """Returns the first KMS client that supports key_uri."""
  warnings.warn(
      'The "tink.kms_client_from_uri" function is deprecated.',
      DeprecationWarning,
      2,
  )
  for client in _kms_clients:
    if client.does_support(key_uri):
      return client
  raise _tink_error.TinkError('No KMS client does support: ' + key_uri)


def reset_kms_clients() -> None:
  """Removes all registered clients. Internal and only used for tests."""
  _kms_clients.clear()
