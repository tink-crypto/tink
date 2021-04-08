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

"""Tests for tink.python.tink.aead_key_templates."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from absl.testing import absltest
from absl.testing import parameterized
from tink.proto import aes_ctr_hmac_aead_pb2
from tink.proto import aes_eax_pb2
from tink.proto import aes_gcm_pb2
from tink.proto import aes_gcm_siv_pb2
from tink.proto import common_pb2
from tink.proto import kms_aead_pb2
from tink.proto import kms_envelope_pb2
from tink.proto import tink_pb2
from tink import aead
from tink.testing import helper


class AeadKeyTemplatesTest(parameterized.TestCase):

  @parameterized.parameters([
      ('AES128_EAX', aead.aead_key_templates.AES128_EAX),
      ('AES256_EAX', aead.aead_key_templates.AES256_EAX),
      ('AES128_GCM', aead.aead_key_templates.AES128_GCM),
      ('AES256_GCM', aead.aead_key_templates.AES256_GCM),
      ('AES128_GCM_SIV', aead.aead_key_templates.AES128_GCM_SIV),
      ('AES256_GCM_SIV', aead.aead_key_templates.AES256_GCM_SIV),
      ('AES128_CTR_HMAC_SHA256',
       aead.aead_key_templates.AES128_CTR_HMAC_SHA256),
      ('AES256_CTR_HMAC_SHA256',
       aead.aead_key_templates.AES256_CTR_HMAC_SHA256),
      ('XCHACHA20_POLY1305', aead.aead_key_templates.XCHACHA20_POLY1305)
  ])
  def test_template(self, template_name, template):
    self.assertEqual(template,
                     helper.template_from_testdata(template_name, 'aead'))

  def test_create_aes_eax_key_template(self):
    # Intentionally using 'weird' or invalid values for parameters,
    # to test that the function correctly puts them in the resulting template.
    template = aead.aead_key_templates.create_aes_eax_key_template(
        key_size=42, iv_size=72)
    self.assertEqual('type.googleapis.com/google.crypto.tink.AesEaxKey',
                     template.type_url)
    self.assertEqual(tink_pb2.TINK, template.output_prefix_type)
    key_format = aes_eax_pb2.AesEaxKeyFormat.FromString(template.value)
    self.assertEqual(42, key_format.key_size)
    self.assertEqual(72, key_format.params.iv_size)

  def test_create_aes_gcm_key_template(self):
    # Intentionally using 'weird' or invalid values for parameters,
    # to test that the function correctly puts them in the resulting template.
    template = aead.aead_key_templates.create_aes_gcm_key_template(key_size=42)
    self.assertEqual('type.googleapis.com/google.crypto.tink.AesGcmKey',
                     template.type_url)
    self.assertEqual(tink_pb2.TINK, template.output_prefix_type)
    key_format = aes_gcm_pb2.AesGcmKeyFormat.FromString(template.value)
    self.assertEqual(42, key_format.key_size)

  def test_create_aes_gcm_siv_key_template(self):
    template = aead.aead_key_templates.create_aes_gcm_siv_key_template(
        key_size=42)
    self.assertEqual('type.googleapis.com/google.crypto.tink.AesGcmSivKey',
                     template.type_url)
    self.assertEqual(tink_pb2.TINK, template.output_prefix_type)
    key_format = aes_gcm_siv_pb2.AesGcmSivKeyFormat.FromString(template.value)
    self.assertEqual(42, key_format.key_size)

  def test_create_aes_ctr_hmac_aead_key_template(self):
    # Intentionally using 'weird' or invalid values for parameters,
    # to test that the function correctly puts them in the resulting template.
    template = aead.aead_key_templates.create_aes_ctr_hmac_aead_key_template(
        aes_key_size=34,
        iv_size=93,
        hmac_key_size=46,
        tag_size=99,
        hash_type=common_pb2.SHA1)
    self.assertEqual('type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey',
                     template.type_url)
    self.assertEqual(tink_pb2.TINK, template.output_prefix_type)
    key_format = aes_ctr_hmac_aead_pb2.AesCtrHmacAeadKeyFormat.FromString(
        template.value)
    self.assertEqual(93, key_format.aes_ctr_key_format.params.iv_size)
    self.assertEqual(34, key_format.aes_ctr_key_format.key_size)
    self.assertEqual(common_pb2.SHA1, key_format.hmac_key_format.params.hash)
    self.assertEqual(99, key_format.hmac_key_format.params.tag_size)
    self.assertEqual(46, key_format.hmac_key_format.key_size)

  def test_create_kms_aead_key_template(self):
    template = aead.aead_key_templates.create_kms_aead_key_template(
        key_uri='fake://kek/uri')
    self.assertEqual(template.type_url,
                     'type.googleapis.com/google.crypto.tink.KmsAeadKey')
    self.assertEqual(template.output_prefix_type, tink_pb2.RAW)
    key_format = kms_aead_pb2.KmsAeadKeyFormat.FromString(template.value)
    self.assertEqual(key_format.key_uri, 'fake://kek/uri')

  def test_create_kms_envelope_aead_key_template(self):
    template = aead.aead_key_templates.create_kms_envelope_aead_key_template(
        kek_uri='fake://kek/uri',
        dek_template=aead.aead_key_templates.AES128_GCM)
    self.assertEqual(
        template.type_url,
        'type.googleapis.com/google.crypto.tink.KmsEnvelopeAeadKey')
    self.assertEqual(template.output_prefix_type, tink_pb2.RAW)
    key_format = kms_envelope_pb2.KmsEnvelopeAeadKeyFormat.FromString(
        template.value)
    self.assertEqual(key_format.kek_uri, 'fake://kek/uri')
    self.assertEqual(key_format.dek_template.type_url,
                     aead.aead_key_templates.AES128_GCM.type_url)


if __name__ == '__main__':
  absltest.main()
