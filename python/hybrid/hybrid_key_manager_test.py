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

"""Tests for tink.python.hybrid_key_manager."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from absl.testing import absltest
from tink.proto import common_pb2
from tink.proto import ecies_aead_hkdf_pb2
from tink.proto import tink_pb2
from tink.python import tink_config
from tink.python.aead import aead_key_templates
from tink.python.core import tink_error
from tink.python.hybrid import hybrid_decrypt
from tink.python.hybrid import hybrid_decrypt_key_manager
from tink.python.hybrid import hybrid_encrypt
from tink.python.hybrid import hybrid_encrypt_key_manager
from tink.python.hybrid import hybrid_key_templates


def setUpModule():
  tink_config.register()


def _hybrid_decrypt_key_manager():
  return hybrid_decrypt_key_manager.from_cc_registry(
      'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey')


def _hybrid_encrypt_key_manager():
  return hybrid_encrypt_key_manager.from_cc_registry(
      'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey')


class HybridKeyManagerTest(absltest.TestCase):

  def test_hybrid_decrypt_primitive_class(self):
    self.assertEqual(_hybrid_decrypt_key_manager().primitive_class(),
                     hybrid_decrypt.HybridDecrypt)

  def test_hybrid_encrypt_primitive_class(self):
    self.assertEqual(_hybrid_encrypt_key_manager().primitive_class(),
                     hybrid_encrypt.HybridEncrypt)

  def test_hybrid_decrypt_key_type(self):
    self.assertEqual(
        _hybrid_decrypt_key_manager().key_type(),
        'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey')

  def test_hybrid_encrypt_key_type(self):
    self.assertEqual(
        _hybrid_encrypt_key_manager().key_type(),
        'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey')

  def test_new_key_data(self):
    key_manager = _hybrid_decrypt_key_manager()
    key_data = key_manager.new_key_data(
        hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM)
    self.assertEqual(key_data.type_url, key_manager.key_type())
    self.assertEqual(key_data.key_material_type,
                     tink_pb2.KeyData.ASYMMETRIC_PRIVATE)
    key = ecies_aead_hkdf_pb2.EciesAeadHkdfPrivateKey()
    key.ParseFromString(key_data.value)
    self.assertLen(key.key_value, 32)
    self.assertEqual(key.public_key.params.kem_params.curve_type,
                     common_pb2.NIST_P256)

  def test_new_key_data_invalid_params_throw_exception(self):
    with self.assertRaisesRegex(tink_error.TinkError,
                                'Unsupported elliptic curve'):
      _hybrid_decrypt_key_manager().new_key_data(
          hybrid_key_templates.create_ecies_aead_hkdf_key_template(
              curve_type=100,
              ec_point_format=common_pb2.UNCOMPRESSED,
              hash_type=common_pb2.SHA256,
              dem_key_template=aead_key_templates.AES128_GCM))

  def test_new_key_data_on_public_key_manager_fails(self):
    key_format = ecies_aead_hkdf_pb2.EciesAeadHkdfKeyFormat()
    key_template = tink_pb2.KeyTemplate()
    key_template.type_url = (
        'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey')
    key_template.value = key_format.SerializeToString()
    key_template.output_prefix_type = tink_pb2.TINK
    with self.assertRaisesRegex(tink_error.TinkError,
                                'Operation not supported for public keys'):
      key_manager = _hybrid_encrypt_key_manager()
      key_manager.new_key_data(key_template)

  def test_encrypt_decrypt(self):
    decrypt_key_manager = _hybrid_decrypt_key_manager()
    encrypt_key_manager = _hybrid_encrypt_key_manager()
    key_data = decrypt_key_manager.new_key_data(
        hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM)
    public_key_data = decrypt_key_manager.public_key_data(key_data)
    hybrid_enc = encrypt_key_manager.primitive(public_key_data)
    ciphertext = hybrid_enc.encrypt(b'some plaintext', b'some context info')
    hybrid_dec = decrypt_key_manager.primitive(key_data)
    self.assertEqual(hybrid_dec.decrypt(ciphertext, b'some context info'),
                     b'some plaintext')

  def test_decrypt_fails(self):
    decrypt_key_manager = _hybrid_decrypt_key_manager()
    key_data = decrypt_key_manager.new_key_data(
        hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM)
    hybrid_dec = decrypt_key_manager.primitive(key_data)
    with self.assertRaisesRegex(tink_error.TinkError, 'ciphertext too short'):
      hybrid_dec.decrypt(b'bad ciphertext', b'some context info')

if __name__ == '__main__':
  absltest.main()
