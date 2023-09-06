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

"""Tests for kms_aead_key_manager."""

from absl.testing import absltest
from tink.proto import kms_aead_pb2
from tink.proto import kms_envelope_pb2
from tink.proto import tink_pb2
import tink
from tink import aead
from tink.aead import _kms_aead_key_manager


def setUpModule():
  aead.register()


class FakeClient(tink.KmsClient):

  def __init__(self, key_uri):
    self.key_uri = key_uri

  def does_support(self, key_uri: str) -> bool:
    return key_uri == self.key_uri

  def get_aead(self, key_uri: str) -> aead.Aead:
    raise NotImplementedError('not implemented')


KMS_AEAD_KEY_TYPE_URL = 'type.googleapis.com/google.crypto.tink.KmsAeadKey'
KMS_ENVELOPE_AEAD_KEY_TYPE_URL = (
    'type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey'
)


class KmsAeadKeyManagerTest(absltest.TestCase):

  def test_kms_aead_new_key_data_success(self):
    client = FakeClient('key_uri')
    tink.register_kms_client(client)
    template = aead.aead_key_templates.create_kms_aead_key_template(
        key_uri='key_uri'
    )
    key_data = _kms_aead_key_manager.KmsAeadKeyManager().new_key_data(template)

    self.assertEqual(key_data.type_url, KMS_AEAD_KEY_TYPE_URL)
    self.assertEqual(key_data.key_material_type, tink_pb2.KeyData.REMOTE)
    key = kms_aead_pb2.KmsAeadKey.FromString(key_data.value)
    self.assertEqual(key.version, 0)
    self.assertEqual(key.params.key_uri, 'key_uri')

  def test_kms_aead_new_key_data_rejects_unknown_template(self):
    with self.assertRaises(tink.TinkError):
      _kms_aead_key_manager.KmsAeadKeyManager().new_key_data(
          aead.aead_key_templates.XCHACHA20_POLY1305_RAW
      )

  def test_kms_aead_primitive_rejects_unknown_key_data(self):
    template = aead.aead_key_templates.create_kms_envelope_aead_key_template(
        kek_uri='kek_uri',
        dek_template=aead.aead_key_templates.XCHACHA20_POLY1305_RAW,
    )
    envelope_aead_key_data = (
        _kms_aead_key_manager.KmsEnvelopeAeadKeyManager().new_key_data(template)
    )

    with self.assertRaises(tink.TinkError):
      _kms_aead_key_manager.KmsAeadKeyManager().primitive(
          envelope_aead_key_data
      )

  def test_kms_envelope_aead_new_key_data_success(self):
    template = aead.aead_key_templates.create_kms_envelope_aead_key_template(
        kek_uri='kek_uri',
        dek_template=aead.aead_key_templates.XCHACHA20_POLY1305_RAW,
    )
    key_data = _kms_aead_key_manager.KmsEnvelopeAeadKeyManager().new_key_data(
        template
    )

    self.assertEqual(key_data.type_url, KMS_ENVELOPE_AEAD_KEY_TYPE_URL)
    self.assertEqual(key_data.key_material_type, tink_pb2.KeyData.REMOTE)
    key = kms_envelope_pb2.KmsEnvelopeAeadKey.FromString(key_data.value)
    self.assertEqual(key.version, 0)
    self.assertEqual(key.params.kek_uri, 'kek_uri')
    self.assertEqual(
        key.params.dek_template, aead.aead_key_templates.XCHACHA20_POLY1305_RAW
    )

  def test_kms_envelope_aead_rejects_unknown_template(self):
    with self.assertRaises(tink.TinkError):
      _kms_aead_key_manager.KmsEnvelopeAeadKeyManager().new_key_data(
          aead.aead_key_templates.XCHACHA20_POLY1305_RAW
      )

  def test_kms_envelope_aead_primitive_rejects_unknown_key_data(self):
    template = aead.aead_key_templates.create_kms_aead_key_template(
        key_uri='key_uri'
    )
    kms_aead_key_data = _kms_aead_key_manager.KmsAeadKeyManager().new_key_data(
        template
    )

    with self.assertRaises(tink.TinkError):
      _kms_aead_key_manager.KmsEnvelopeAeadKeyManager().primitive(
          kms_aead_key_data
      )


if __name__ == '__main__':
  absltest.main()
