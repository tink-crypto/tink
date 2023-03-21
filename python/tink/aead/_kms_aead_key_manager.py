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

"""Python KMS AEAD key manager."""

import abc

from typing import List, Type

from tink.proto import kms_aead_pb2
from tink.proto import kms_envelope_pb2
from tink.proto import tink_pb2
from tink import core
from tink.aead import _aead
from tink.aead import _kms_envelope_aead


class KmsClient(metaclass=abc.ABCMeta):

  @abc.abstractmethod
  def does_support(self, key_uri: str) -> bool:
    raise NotImplementedError()

  @abc.abstractmethod
  def get_aead(self, key_uri: str) -> _aead.Aead:
    raise NotImplementedError()


_kms_clients: List[KmsClient] = []


def register_kms_client(client: KmsClient) -> None:
  """Tink-internal function to register kms clients."""
  _kms_clients.append(client)


def _kms_client_from_uri(key_uri: str) -> KmsClient:
  """Tink-internal function to get a KmsClient."""
  for client in _kms_clients:
    if client.does_support(key_uri):
      return client
  raise core.TinkError('No KMS client does support: ' + key_uri)


_KMS_AEAD_KEY_TYPE_URL = 'type.googleapis.com/google.crypto.tink.KmsAeadKey'
_KMS_ENVELOPE_AEAD_KEY_TYPE_URL = (
    'type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey'
)


class KmsAeadKeyManager(core.KeyManager[_aead.Aead]):
  """KmsAeadKeyManager."""

  def primitive_class(self) -> Type[_aead.Aead]:
    return _aead.Aead

  def primitive(self, key_data: tink_pb2.KeyData) -> _aead.Aead:
    if key_data.type_url != _KMS_AEAD_KEY_TYPE_URL:
      raise core.TinkError('wrong key type: ' + key_data.type_url)
    kms_key = kms_aead_pb2.KmsAeadKey.FromString(key_data.value)
    client = _kms_client_from_uri(kms_key.params.key_uri)
    return client.get_aead(key_uri=kms_key.params.key_uri)

  def key_type(self) -> str:
    return _KMS_AEAD_KEY_TYPE_URL

  def new_key_data(
      self, key_template: tink_pb2.KeyTemplate
  ) -> tink_pb2.KeyData:
    if key_template.type_url != _KMS_AEAD_KEY_TYPE_URL:
      raise core.TinkError('wrong key type: ' + key_template.type_url)
    key = kms_aead_pb2.KmsAeadKey(
        version=0,
        params=kms_aead_pb2.KmsAeadKeyFormat.FromString(key_template.value),
    )
    return tink_pb2.KeyData(
        type_url=_KMS_AEAD_KEY_TYPE_URL,
        value=key.SerializeToString(),
        key_material_type=tink_pb2.KeyData.REMOTE,
    )

  def does_support(self, type_url: str) -> bool:
    return self.key_type() == type_url


class KmsEnvelopeAeadKeyManager(core.KeyManager[_aead.Aead]):
  """KmsEnvelopeAeadKeyManager."""

  def primitive_class(self) -> Type[_aead.Aead]:
    return _aead.Aead

  def primitive(self, key_data: tink_pb2.KeyData) -> _aead.Aead:
    if key_data.type_url != _KMS_ENVELOPE_AEAD_KEY_TYPE_URL:
      raise core.TinkError('wrong key type: ' + key_data.type_url)
    env_key = kms_envelope_pb2.KmsEnvelopeAeadKey.FromString(key_data.value)
    client = _kms_client_from_uri(env_key.params.kek_uri)

    return _kms_envelope_aead.KmsEnvelopeAead(
        env_key.params.dek_template,
        client.get_aead(key_uri=env_key.params.kek_uri),
    )

  def key_type(self) -> str:
    return _KMS_ENVELOPE_AEAD_KEY_TYPE_URL

  def new_key_data(
      self, key_template: tink_pb2.KeyTemplate
  ) -> tink_pb2.KeyData:
    if key_template.type_url != _KMS_ENVELOPE_AEAD_KEY_TYPE_URL:
      raise core.TinkError('wrong key type: ' + key_template.type_url)
    env_key = kms_envelope_pb2.KmsEnvelopeAeadKey(
        version=0,
        params=kms_envelope_pb2.KmsEnvelopeAeadKeyFormat.FromString(
            key_template.value
        ),
    )
    return tink_pb2.KeyData(
        type_url=_KMS_ENVELOPE_AEAD_KEY_TYPE_URL,
        value=env_key.SerializeToString(),
        key_material_type=tink_pb2.KeyData.REMOTE,
    )

  def does_support(self, type_url: str) -> bool:
    return self.key_type() == type_url
