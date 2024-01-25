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


from typing import Type

from tink.proto import kms_aead_pb2
from tink.proto import kms_envelope_pb2
from tink.proto import tink_pb2
from tink import _kms_clients
from tink import core
from tink.aead import _aead
from tink.aead import _kms_envelope_aead


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
    client = _kms_clients.kms_client_from_uri(kms_key.params.key_uri)
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
    client = _kms_clients.kms_client_from_uri(env_key.params.kek_uri)

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
    params = kms_envelope_pb2.KmsEnvelopeAeadKeyFormat.FromString(
        key_template.value
    )
    if not _kms_envelope_aead.is_supported_dek_key_type(
        params.dek_template.type_url
    ):
      raise core.TinkError(
          'Unsupported DEK key type: %s' % key_template.type_url
      )
    env_key = kms_envelope_pb2.KmsEnvelopeAeadKey(
        version=0,
        params=params,
    )
    return tink_pb2.KeyData(
        type_url=_KMS_ENVELOPE_AEAD_KEY_TYPE_URL,
        value=env_key.SerializeToString(),
        key_material_type=tink_pb2.KeyData.REMOTE,
    )

  def does_support(self, type_url: str) -> bool:
    return self.key_type() == type_url
