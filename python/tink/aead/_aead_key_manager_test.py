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

"""Tests for tink.python.tink.aead_key_manager."""

from absl.testing import absltest
from absl.testing import parameterized
from tink.proto import aes_ctr_hmac_aead_pb2
from tink.proto import aes_eax_pb2
from tink.proto import aes_gcm_pb2
from tink.proto import aes_gcm_siv_pb2
from tink.proto import common_pb2
from tink.proto import tink_pb2
from tink.proto import xchacha20_poly1305_pb2
import tink
from tink import aead
from tink import core
from tink import mac
from tink.testing import fake_kms


FAKE_KMS_URI = 'fake-kms://CM2b3_MDElQKSAowdHlwZS5nb29nbGVhcGlzLmNvbS9nb29nbGUuY3J5cHRvLnRpbmsuQWVzR2NtS2V5EhIaEIK75t5L-adlUwVhWvRuWUwYARABGM2b3_MDIAE'


def setUpModule():
  aead.register()
  fake_kms.register_client()


class AeadKeyManagerTest(parameterized.TestCase):

  def test_new_key_data_aes_eax(self):
    key_template = aead.aead_key_templates.create_aes_eax_key_template(
        key_size=16, iv_size=12)
    key_manager = core.Registry.key_manager(key_template.type_url)
    key_data = key_manager.new_key_data(key_template)
    self.assertEqual(key_data.type_url, key_template.type_url)
    self.assertEqual(key_data.key_material_type, tink_pb2.KeyData.SYMMETRIC)
    key = aes_eax_pb2.AesEaxKey.FromString(key_data.value)
    self.assertEqual(key.version, 0)
    self.assertEqual(key.params.iv_size, 12)
    self.assertLen(key.key_value, 16)

  def test_new_key_data_aes_gcm(self):
    key_template = aead.aead_key_templates.create_aes_gcm_key_template(
        key_size=16)
    key_manager = core.Registry.key_manager(key_template.type_url)
    key_data = key_manager.new_key_data(key_template)
    self.assertEqual(key_data.type_url, key_template.type_url)
    self.assertEqual(key_data.key_material_type, tink_pb2.KeyData.SYMMETRIC)
    key = aes_gcm_pb2.AesGcmKey.FromString(key_data.value)
    self.assertEqual(key.version, 0)
    self.assertLen(key.key_value, 16)

  def test_new_key_data_aes_ctr_hmac_aead(self):
    template = aead.aead_key_templates.create_aes_ctr_hmac_aead_key_template(
        aes_key_size=16,
        iv_size=12,
        hmac_key_size=32,
        tag_size=16,
        hash_type=common_pb2.SHA256)
    key_manager = core.Registry.key_manager(template.type_url)
    key_data = key_manager.new_key_data(template)
    self.assertEqual(key_data.type_url, template.type_url)
    self.assertEqual(key_data.key_material_type, tink_pb2.KeyData.SYMMETRIC)
    key = aes_ctr_hmac_aead_pb2.AesCtrHmacAeadKey.FromString(key_data.value)
    self.assertEqual(key.version, 0)
    self.assertEqual(key.aes_ctr_key.version, 0)
    self.assertLen(key.aes_ctr_key.key_value, 16)
    self.assertEqual(key.aes_ctr_key.params.iv_size, 12)
    self.assertEqual(key.hmac_key.version, 0)
    self.assertLen(key.hmac_key.key_value, 32)
    self.assertEqual(key.hmac_key.params.tag_size, 16)
    self.assertEqual(key.hmac_key.params.hash, common_pb2.SHA256)

  def test_new_key_data_aes_gcm_siv(self):
    key_template = aead.aead_key_templates.create_aes_gcm_siv_key_template(
        key_size=16)
    key_manager = core.Registry.key_manager(key_template.type_url)
    key_data = key_manager.new_key_data(key_template)
    self.assertEqual(key_data.type_url, key_template.type_url)
    self.assertEqual(key_data.key_material_type, tink_pb2.KeyData.SYMMETRIC)
    key = aes_gcm_siv_pb2.AesGcmSivKey.FromString(key_data.value)
    self.assertEqual(key.version, 0)
    self.assertLen(key.key_value, 16)

  def test_new_key_data_xchacha20_poly1305(self):
    template = aead.aead_key_templates.XCHACHA20_POLY1305
    key_manager = core.Registry.key_manager(template.type_url)
    key_data = key_manager.new_key_data(template)
    self.assertEqual(key_data.type_url, template.type_url)
    self.assertEqual(key_data.key_material_type, tink_pb2.KeyData.SYMMETRIC)
    key = xchacha20_poly1305_pb2.XChaCha20Poly1305Key.FromString(key_data.value)
    self.assertEqual(key.version, 0)
    self.assertLen(key.key_value, 32)

  def test_invalid_params_throw_exception_aes_eax(self):
    template = aead.aead_key_templates.create_aes_eax_key_template(
        key_size=16, iv_size=9)
    with self.assertRaises(tink.TinkError):
      tink.new_keyset_handle(template)

  def test_invalid_params_throw_exception_aes_gcm(self):
    template = aead.aead_key_templates.create_aes_gcm_key_template(
        key_size=17)
    with self.assertRaises(tink.TinkError):
      tink.new_keyset_handle(template)

  def test_invalid_params_throw_exception_aes_ctr_hmac_aead(self):
    template = aead.aead_key_templates.create_aes_ctr_hmac_aead_key_template(
        aes_key_size=42,
        iv_size=16,
        hmac_key_size=32,
        tag_size=32,
        hash_type=common_pb2.SHA256)
    with self.assertRaises(tink.TinkError):
      tink.new_keyset_handle(template)

  @parameterized.parameters([
      aead.aead_key_templates.AES128_EAX,
      aead.aead_key_templates.AES256_EAX,
      aead.aead_key_templates.AES128_GCM,
      aead.aead_key_templates.AES256_GCM,
      aead.aead_key_templates.AES128_GCM_SIV,
      aead.aead_key_templates.AES256_GCM_SIV,
      aead.aead_key_templates.AES128_CTR_HMAC_SHA256,
      aead.aead_key_templates.AES256_CTR_HMAC_SHA256,
      aead.aead_key_templates.XCHACHA20_POLY1305])
  def test_encrypt_decrypt_success(self, template):
    keyset_handle = tink.new_keyset_handle(template)
    primitive = keyset_handle.primitive(aead.Aead)
    plaintext = b'plaintext'
    associated_data = b'associated_data'
    ciphertext = primitive.encrypt(plaintext, associated_data)
    self.assertEqual(primitive.decrypt(ciphertext, associated_data), plaintext)

  def test_kms_aead_encrypt_decrypt_success(self):
    template = aead.aead_key_templates.create_kms_aead_key_template(
        key_uri=FAKE_KMS_URI)
    keyset_handle = tink.new_keyset_handle(template)
    primitive = keyset_handle.primitive(aead.Aead)
    plaintext = b'plaintext'
    associated_data = b'associated_data'
    ciphertext = primitive.encrypt(plaintext, associated_data)
    self.assertEqual(primitive.decrypt(ciphertext, associated_data), plaintext)

  def test_kms_aead_with_unknown_key_uri_fails(self):
    template = aead.aead_key_templates.create_kms_aead_key_template(
        key_uri='unknown-kms://key_uri')
    handle = tink.new_keyset_handle(template)
    with self.assertRaises(tink.TinkError):
      handle.primitive(aead.Aead)

  def test_kms_envelope_aead_encrypt_decrypt_success(self):
    template = aead.aead_key_templates.create_kms_envelope_aead_key_template(
        kek_uri=FAKE_KMS_URI, dek_template=aead.aead_key_templates.AES128_GCM
    )
    keyset_handle = tink.new_keyset_handle(template)
    primitive = keyset_handle.primitive(aead.Aead)
    plaintext = b'plaintext'
    associated_data = b'associated_data'
    ciphertext = primitive.encrypt(plaintext, associated_data)
    self.assertEqual(primitive.decrypt(ciphertext, associated_data), plaintext)

  def test_kms_envelope_aead_with_unknown_key_uri_fails(self):
    template = aead.aead_key_templates.create_kms_envelope_aead_key_template(
        kek_uri='unknown-kms://key_uri',
        dek_template=aead.aead_key_templates.AES128_GCM,
    )
    handle = tink.new_keyset_handle(template)
    with self.assertRaises(tink.TinkError):
      handle.primitive(aead.Aead)

  def test_kms_envelope_aead_with_invalid_dek_template_fails(self):
    template = aead.aead_key_templates.create_kms_envelope_aead_key_template(
        kek_uri=FAKE_KMS_URI,
        dek_template=mac.mac_key_templates.HMAC_SHA256_128BITTAG,
    )
    with self.assertRaises(tink.TinkError):
      _ = tink.new_keyset_handle(template)

  def test_kms_envelope_aead_with_envelope_template_as_dek_template_fails(self):
    env_template = (
        aead.aead_key_templates.create_kms_envelope_aead_key_template(
            kek_uri=FAKE_KMS_URI,
            dek_template=aead.aead_key_templates.AES128_GCM,
        )
    )
    template = aead.aead_key_templates.create_kms_envelope_aead_key_template(
        kek_uri=FAKE_KMS_URI,
        dek_template=env_template,
    )
    with self.assertRaises(tink.TinkError):
      _ = tink.new_keyset_handle(template)

  def test_kms_envelope_aead_with_kms_template_as_dek_template_fails(self):
    kms_template = aead.aead_key_templates.create_kms_aead_key_template(
        key_uri=FAKE_KMS_URI,
    )
    template = aead.aead_key_templates.create_kms_envelope_aead_key_template(
        kek_uri=FAKE_KMS_URI,
        dek_template=kms_template,
    )
    with self.assertRaises(tink.TinkError):
      _ = tink.new_keyset_handle(template)

  def test_kms_envelope_aead_decrypt_fixed_ciphertext_success(self):
    # This keyset contains a single KmsEnvelopeAeadKey with
    # kek_uri = FAKE_KMS_URI and dek_template = AES128_GCM.
    json_keyset = '''{
      "primaryKeyId": 371374440,
      "key": [
        {
          "keyData": {
            "typeUrl": "type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey",
            "value": "EsMBEjgYARICEBAKMHR5cGUuZ29vZ2xlYXBpcy5jb20vZ29vZ2xlLmNyeXB0by50aW5rLkFlc0djbUtleQqGAWZha2Uta21zOi8vQ00yYjNfTURFbFFLU0Fvd2RIbHdaUzVuYjI5bmJHVmhjR2x6TG1OdmJTOW5iMjluYkdVdVkzSjVjSFJ2TG5ScGJtc3VRV1Z6UjJOdFMyVjVFaElhRUlLNzV0NUwtYWRsVXdWaFd2UnVXVXdZQVJBQkdNMmIzX01ESUFF",
            "keyMaterialType": "REMOTE"
          },
          "status": "ENABLED",
          "keyId": 371374440,
          "outputPrefixType": "RAW"
        }
      ]
    }'''
    keyset_handle = tink.json_proto_keyset_format.parse_without_secret(
        json_keyset
    )

    ciphertext = bytes.fromhex(
        '00000033013e77cdcd39016d632a3bb83b694565d3d2d85329ccc3aff540'
        'ef00a7dcb95c157f0199fa7af825a2da2cf2ed0818e6eb0becb39d73d1b1'
        '26e60bdac2dbe7d742dabaedcc2b3809e429510d9a330dc9e2bb1dc9d5b59ecc'
    )
    primitive = keyset_handle.primitive(aead.Aead)
    decrypted = primitive.decrypt(ciphertext, b'associated_data')
    self.assertEqual(decrypted, b'plaintext')

  @parameterized.parameters([
      aead.aead_key_templates.AES128_EAX,
      aead.aead_key_templates.AES256_EAX,
      aead.aead_key_templates.AES128_GCM,
      aead.aead_key_templates.AES256_GCM,
      aead.aead_key_templates.AES128_GCM_SIV,
      aead.aead_key_templates.AES256_GCM_SIV,
      aead.aead_key_templates.AES128_CTR_HMAC_SHA256,
      aead.aead_key_templates.AES256_CTR_HMAC_SHA256,
      aead.aead_key_templates.XCHACHA20_POLY1305])
  def test_invalid_decrypt_raises_error(self, template):
    keyset_handle = tink.new_keyset_handle(template)
    primitive = keyset_handle.primitive(aead.Aead)
    with self.assertRaises(tink.TinkError):
      primitive.decrypt(b'invalid ciphertext', b'ad')


if __name__ == '__main__':
  absltest.main()
