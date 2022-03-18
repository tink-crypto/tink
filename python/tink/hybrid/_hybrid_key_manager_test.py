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

"""Tests for tink.python.tink.hybrid_key_manager."""

from typing import cast
from absl.testing import absltest
from absl.testing import parameterized
from tink.proto import common_pb2
from tink.proto import ecies_aead_hkdf_pb2
from tink.proto import hpke_pb2
from tink.proto import tink_pb2
import tink
from tink import aead
from tink import core
from tink import hybrid


def setUpModule():
  hybrid.register()


class HybridKeyManagerTest(parameterized.TestCase):

  def test_new_key_data(self):
    tmpl = hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM
    key_manager = core.Registry.key_manager(tmpl.type_url)
    key_data = key_manager.new_key_data(tmpl)
    self.assertEqual(key_data.type_url, key_manager.key_type())
    self.assertEqual(key_data.key_material_type,
                     tink_pb2.KeyData.ASYMMETRIC_PRIVATE)
    key = ecies_aead_hkdf_pb2.EciesAeadHkdfPrivateKey.FromString(key_data.value)
    self.assertLen(key.key_value, 32)
    self.assertEqual(key.public_key.params.kem_params.curve_type,
                     common_pb2.NIST_P256)

  def test_new_keyset_handle_invalid_params_throw_exception(self):
    templates = hybrid.hybrid_key_templates
    key_template = templates.create_ecies_aead_hkdf_key_template(
        curve_type=cast(common_pb2.EllipticCurveType, 100),
        ec_point_format=common_pb2.UNCOMPRESSED,
        hash_type=common_pb2.SHA256,
        dem_key_template=aead.aead_key_templates.AES128_GCM)
    with self.assertRaises(core.TinkError):
      tink.new_keyset_handle(key_template)

  def test_new_keyset_handle_on_public_key_fails(self):
    key_format = ecies_aead_hkdf_pb2.EciesAeadHkdfKeyFormat()
    key_template = tink_pb2.KeyTemplate()
    key_template.type_url = (
        'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey')
    key_template.value = key_format.SerializeToString()
    key_template.output_prefix_type = tink_pb2.TINK
    with self.assertRaises(core.TinkError):
      tink.new_keyset_handle(key_template)

  @parameterized.parameters([
      hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM, hybrid
      .hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256
  ])
  def test_encrypt_decrypt(self, template):
    private_handle = tink.new_keyset_handle(template)
    public_handle = private_handle.public_keyset_handle()
    hybrid_enc = public_handle.primitive(hybrid.HybridEncrypt)
    ciphertext = hybrid_enc.encrypt(b'some plaintext', b'some context info')
    hybrid_dec = private_handle.primitive(hybrid.HybridDecrypt)
    self.assertEqual(hybrid_dec.decrypt(ciphertext, b'some context info'),
                     b'some plaintext')

  @parameterized.parameters([
      hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM, hybrid
      .hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256
  ])
  def test_decrypt_fails(self, template):
    private_handle = tink.new_keyset_handle(template)
    hybrid_dec = private_handle.primitive(hybrid.HybridDecrypt)
    with self.assertRaises(core.TinkError):
      hybrid_dec.decrypt(b'bad ciphertext', b'some context info')


class HpkeKeyManagerTest(parameterized.TestCase):

  def test_new_key_data(self):
    tmpl = hybrid.hybrid_key_templates.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM
    key_manager = core.Registry.key_manager(tmpl.type_url)
    key_data = key_manager.new_key_data(tmpl)
    self.assertEqual(key_data.type_url, key_manager.key_type())
    self.assertEqual(key_data.key_material_type,
                     tink_pb2.KeyData.ASYMMETRIC_PRIVATE)
    key = hpke_pb2.HpkePrivateKey.FromString(key_data.value)
    self.assertLen(key.private_key, 32)  # HPKE 'Nsk' parameter length  = 32
    self.assertEqual(key.public_key.params.kem,
                     hpke_pb2.DHKEM_X25519_HKDF_SHA256)
    self.assertEqual(key.public_key.params.kdf, hpke_pb2.HKDF_SHA256)
    self.assertEqual(key.public_key.params.aead, hpke_pb2.AES_128_GCM)

  def test_new_keyset_handle_invalid_kem_raises_exception(self):
    templates = hybrid.hybrid_key_templates
    key_template = templates._create_hpke_key_template(
        hpke_kem=hpke_pb2.KEM_UNKNOWN,
        hpke_kdf=hpke_pb2.HKDF_SHA256,
        hpke_aead=hpke_pb2.AES_128_GCM,
        output_prefix_type=tink_pb2.TINK)
    with self.assertRaises(core.TinkError):
      tink.new_keyset_handle(key_template)

  def test_new_keyset_handle_invalid_kdf_raises_exception(self):
    templates = hybrid.hybrid_key_templates
    key_template = templates._create_hpke_key_template(
        hpke_kem=hpke_pb2.DHKEM_X25519_HKDF_SHA256,
        hpke_kdf=hpke_pb2.KDF_UNKNOWN,
        hpke_aead=hpke_pb2.AES_128_GCM,
        output_prefix_type=tink_pb2.TINK)
    with self.assertRaises(core.TinkError):
      tink.new_keyset_handle(key_template)

  def test_new_keyset_handle_invalid_aead_raises_exception(self):
    templates = hybrid.hybrid_key_templates
    key_template = templates._create_hpke_key_template(
        hpke_kem=hpke_pb2.DHKEM_X25519_HKDF_SHA256,
        hpke_kdf=hpke_pb2.HKDF_SHA256,
        hpke_aead=hpke_pb2.AEAD_UNKNOWN,
        output_prefix_type=tink_pb2.TINK)
    with self.assertRaises(core.TinkError):
      tink.new_keyset_handle(key_template)

  def test_new_keyset_handle_on_public_key_fails(self):
    key_format = hpke_pb2.HpkeKeyFormat()
    key_template = tink_pb2.KeyTemplate()
    key_template.type_url = (
        'type.googleapis.com/google.crypto.tink.HpkePublicKey')
    key_template.value = key_format.SerializeToString()
    key_template.output_prefix_type = tink_pb2.TINK
    with self.assertRaises(core.TinkError):
      tink.new_keyset_handle(key_template)

  @parameterized.parameters([
      hybrid.hybrid_key_templates
      .DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM,
      hybrid.hybrid_key_templates
      .DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_RAW, hybrid
      .hybrid_key_templates.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM,
      hybrid.hybrid_key_templates
      .DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_RAW,
      hybrid.hybrid_key_templates
      .DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305,
      hybrid.hybrid_key_templates
      .DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_RAW
  ])
  def test_encrypt_decrypt(self, template):
    private_handle = tink.new_keyset_handle(template)
    public_handle = private_handle.public_keyset_handle()
    hybrid_encrypt = public_handle.primitive(hybrid.HybridEncrypt)
    ciphertext = hybrid_encrypt.encrypt(b'some plaintext', b'some context info')
    hybrid_decrypt = private_handle.primitive(hybrid.HybridDecrypt)
    self.assertEqual(
        hybrid_decrypt.decrypt(ciphertext, b'some context info'),
        b'some plaintext')

  @parameterized.parameters([
      hybrid.hybrid_key_templates
      .DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM,
      hybrid.hybrid_key_templates
      .DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM_RAW, hybrid
      .hybrid_key_templates.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM,
      hybrid.hybrid_key_templates
      .DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_256_GCM_RAW,
      hybrid.hybrid_key_templates
      .DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305,
      hybrid.hybrid_key_templates
      .DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_CHACHA20_POLY1305_RAW
  ])
  def test_decrypt_fails(self, template):
    private_handle = tink.new_keyset_handle(template)
    hybrid_decrypt = private_handle.primitive(hybrid.HybridDecrypt)
    with self.assertRaises(core.TinkError):
      hybrid_decrypt.decrypt(b'bad ciphertext', b'some context info')

if __name__ == '__main__':
  absltest.main()
