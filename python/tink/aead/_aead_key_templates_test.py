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
from tink.proto import aes_ctr_hmac_aead_pb2
from tink.proto import aes_eax_pb2
from tink.proto import aes_gcm_pb2
from tink.proto import aes_gcm_siv_pb2
from tink.proto import common_pb2
from tink.proto import tink_pb2
from tink import aead


class AeadKeyTemplatesTest(absltest.TestCase):

  def test_aes128_eax(self):
    template = aead.aead_key_templates.AES128_EAX
    self.assertEqual('type.googleapis.com/google.crypto.tink.AesEaxKey',
                     template.type_url)
    self.assertEqual(tink_pb2.TINK, template.output_prefix_type)
    key_format = aes_eax_pb2.AesEaxKeyFormat()
    key_format.ParseFromString(template.value)
    self.assertEqual(16, key_format.key_size)
    self.assertEqual(16, key_format.params.iv_size)

  def test_aes256_eax(self):
    template = aead.aead_key_templates.AES256_EAX
    self.assertEqual('type.googleapis.com/google.crypto.tink.AesEaxKey',
                     template.type_url)
    self.assertEqual(tink_pb2.TINK, template.output_prefix_type)
    key_format = aes_eax_pb2.AesEaxKeyFormat()
    key_format.ParseFromString(template.value)
    self.assertEqual(32, key_format.key_size)
    self.assertEqual(16, key_format.params.iv_size)

  def test_create_aes_eax_key_template(self):
    # Intentionally using 'weird' or invalid values for parameters,
    # to test that the function correctly puts them in the resulting template.
    template = aead.aead_key_templates.create_aes_eax_key_template(
        key_size=42, iv_size=72)
    self.assertEqual('type.googleapis.com/google.crypto.tink.AesEaxKey',
                     template.type_url)
    self.assertEqual(tink_pb2.TINK, template.output_prefix_type)
    key_format = aes_eax_pb2.AesEaxKeyFormat()
    key_format.ParseFromString(template.value)
    self.assertEqual(42, key_format.key_size)
    self.assertEqual(72, key_format.params.iv_size)

  def test_aes128_gcm(self):
    template = aead.aead_key_templates.AES128_GCM
    self.assertEqual('type.googleapis.com/google.crypto.tink.AesGcmKey',
                     template.type_url)
    self.assertEqual(tink_pb2.TINK, template.output_prefix_type)
    key_format = aes_gcm_pb2.AesGcmKeyFormat()
    key_format.ParseFromString(template.value)
    self.assertEqual(16, key_format.key_size)

  def test_aes256_gcm(self):
    template = aead.aead_key_templates.AES256_GCM
    self.assertEqual('type.googleapis.com/google.crypto.tink.AesGcmKey',
                     template.type_url)
    self.assertEqual(tink_pb2.TINK, template.output_prefix_type)
    key_format = aes_gcm_pb2.AesGcmKeyFormat()
    key_format.ParseFromString(template.value)
    self.assertEqual(32, key_format.key_size)

  def test_create_aes_gcm_key_template(self):
    # Intentionally using 'weird' or invalid values for parameters,
    # to test that the function correctly puts them in the resulting template.
    template = aead.aead_key_templates.create_aes_gcm_key_template(key_size=42)
    self.assertEqual('type.googleapis.com/google.crypto.tink.AesGcmKey',
                     template.type_url)
    self.assertEqual(tink_pb2.TINK, template.output_prefix_type)
    key_format = aes_gcm_pb2.AesGcmKeyFormat()
    key_format.ParseFromString(template.value)
    self.assertEqual(42, key_format.key_size)

  def test_aes128_gcm_siv(self):
    template = aead.aead_key_templates.AES128_GCM_SIV
    self.assertEqual('type.googleapis.com/google.crypto.tink.AesGcmSivKey',
                     template.type_url)
    self.assertEqual(tink_pb2.TINK, template.output_prefix_type)
    key_format = aes_gcm_siv_pb2.AesGcmSivKeyFormat()
    key_format.ParseFromString(template.value)
    self.assertEqual(16, key_format.key_size)

  def test_aes256_gcm_siv(self):
    template = aead.aead_key_templates.AES256_GCM_SIV
    self.assertEqual('type.googleapis.com/google.crypto.tink.AesGcmSivKey',
                     template.type_url)
    self.assertEqual(tink_pb2.TINK, template.output_prefix_type)
    key_format = aes_gcm_siv_pb2.AesGcmSivKeyFormat()
    key_format.ParseFromString(template.value)
    self.assertEqual(32, key_format.key_size)

  def test_create_aes_gcm_siv_key_template(self):
    template = aead.aead_key_templates.create_aes_gcm_siv_key_template(
        key_size=42)
    self.assertEqual('type.googleapis.com/google.crypto.tink.AesGcmSivKey',
                     template.type_url)
    self.assertEqual(tink_pb2.TINK, template.output_prefix_type)
    key_format = aes_gcm_siv_pb2.AesGcmSivKeyFormat()
    key_format.ParseFromString(template.value)
    self.assertEqual(42, key_format.key_size)

  def test_aes256_ctr_hmac_sha256(self):
    template = aead.aead_key_templates.AES128_CTR_HMAC_SHA256
    self.assertEqual('type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey',
                     template.type_url)
    self.assertEqual(tink_pb2.TINK, template.output_prefix_type)
    key_format = aes_ctr_hmac_aead_pb2.AesCtrHmacAeadKeyFormat()
    key_format.ParseFromString(template.value)
    self.assertEqual(16, key_format.aes_ctr_key_format.params.iv_size)
    self.assertEqual(16, key_format.aes_ctr_key_format.key_size)
    self.assertEqual(common_pb2.SHA256, key_format.hmac_key_format.params.hash)
    self.assertEqual(16, key_format.hmac_key_format.params.tag_size)
    self.assertEqual(32, key_format.hmac_key_format.key_size)

  def test_aes128_ctr_hmac_sha256(self):
    template = aead.aead_key_templates.AES256_CTR_HMAC_SHA256
    self.assertEqual('type.googleapis.com/google.crypto.tink.AesCtrHmacAeadKey',
                     template.type_url)
    self.assertEqual(tink_pb2.TINK, template.output_prefix_type)
    key_format = aes_ctr_hmac_aead_pb2.AesCtrHmacAeadKeyFormat()
    key_format.ParseFromString(template.value)
    self.assertEqual(16, key_format.aes_ctr_key_format.params.iv_size)
    self.assertEqual(32, key_format.aes_ctr_key_format.key_size)
    self.assertEqual(common_pb2.SHA256, key_format.hmac_key_format.params.hash)
    self.assertEqual(32, key_format.hmac_key_format.params.tag_size)
    self.assertEqual(32, key_format.hmac_key_format.key_size)

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
    key_format = aes_ctr_hmac_aead_pb2.AesCtrHmacAeadKeyFormat()
    key_format.ParseFromString(template.value)
    self.assertEqual(93, key_format.aes_ctr_key_format.params.iv_size)
    self.assertEqual(34, key_format.aes_ctr_key_format.key_size)
    self.assertEqual(common_pb2.SHA1, key_format.hmac_key_format.params.hash)
    self.assertEqual(99, key_format.hmac_key_format.params.tag_size)
    self.assertEqual(46, key_format.hmac_key_format.key_size)

  def test_xchacha20_poly1305(self):
    template = aead.aead_key_templates.XCHACHA20_POLY1305
    self.assertEqual(
        'type.googleapis.com/google.crypto.tink.XChaCha20Poly1305Key',
        template.type_url)
    self.assertEqual(tink_pb2.TINK, template.output_prefix_type)

if __name__ == '__main__':
  absltest.main()
