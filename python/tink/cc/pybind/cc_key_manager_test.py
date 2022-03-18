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

"""Tests for tink.python.tink.cc.pybind.py_key_manager."""

from typing import cast
from absl.testing import absltest
from absl.testing import parameterized
from tink.proto import aes_eax_pb2
from tink.proto import aes_siv_pb2
from tink.proto import common_pb2
from tink.proto import ecdsa_pb2
from tink.proto import ecies_aead_hkdf_pb2
from tink.proto import hmac_pb2
from tink.proto import hmac_prf_pb2
from tink.proto import hpke_pb2
from tink.proto import jwt_ecdsa_pb2
from tink.proto import jwt_hmac_pb2
from tink.proto import tink_pb2
from tink import aead
from tink import hybrid
from tink.cc.pybind import tink_bindings


def setUpModule():
  tink_bindings.register()
  tink_bindings.register_jwt()
  tink_bindings.register_hpke()


class AeadKeyManagerTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.key_manager = tink_bindings.AeadKeyManager.from_cc_registry(
        'type.googleapis.com/google.crypto.tink.AesEaxKey')

  def new_aes_eax_key_template(self, iv_size, key_size):
    key_format = aes_eax_pb2.AesEaxKeyFormat()
    key_format.params.iv_size = iv_size
    key_format.key_size = key_size
    key_template = tink_pb2.KeyTemplate()
    key_template.type_url = 'type.googleapis.com/google.crypto.tink.AesEaxKey'
    key_template.value = key_format.SerializeToString()
    return key_template.SerializeToString()

  def test_key_type(self):
    self.assertEqual(self.key_manager.key_type(),
                     'type.googleapis.com/google.crypto.tink.AesEaxKey')

  def test_new_key_data(self):
    key_template = self.new_aes_eax_key_template(12, 16)
    serialized_key_data = self.key_manager.new_key_data(key_template)
    key_data = tink_pb2.KeyData.FromString(serialized_key_data)
    self.assertEqual(key_data.type_url, self.key_manager.key_type())
    self.assertEqual(key_data.key_material_type, tink_pb2.KeyData.SYMMETRIC)
    key = aes_eax_pb2.AesEaxKey.FromString(key_data.value)
    self.assertEqual(key.version, 0)
    self.assertEqual(key.params.iv_size, 12)
    self.assertLen(key.key_value, 16)

  def test_invalid_params_raise_exception(self):
    key_template = self.new_aes_eax_key_template(9, 16)
    with self.assertRaises(tink_bindings.PythonTinkException):
      self.key_manager.new_key_data(key_template)

  def test_encrypt_decrypt(self):
    key_template = self.new_aes_eax_key_template(12, 16)
    key_data = self.key_manager.new_key_data(key_template)

    primitive = self.key_manager.primitive(key_data)
    plaintext = b'plaintext'
    associated_data = b'associated_data'
    ciphertext = primitive.encrypt(plaintext, associated_data)
    self.assertEqual(primitive.decrypt(ciphertext, associated_data), plaintext)


class DeterministicAeadKeyManagerTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    daead_key_manager = tink_bindings.DeterministicAeadKeyManager
    self.key_manager = daead_key_manager.from_cc_registry(
        'type.googleapis.com/google.crypto.tink.AesSivKey')

  def new_aes_siv_key_template(self, key_size):
    key_format = aes_siv_pb2.AesSivKeyFormat()
    key_format.key_size = key_size
    key_template = tink_pb2.KeyTemplate()
    key_template.type_url = 'type.googleapis.com/google.crypto.tink.AesSivKey'
    key_template.value = key_format.SerializeToString()
    return key_template.SerializeToString()

  def test_key_type(self):
    self.assertEqual(self.key_manager.key_type(),
                     'type.googleapis.com/google.crypto.tink.AesSivKey')

  def test_new_key_data(self):
    key_template = self.new_aes_siv_key_template(64)
    key_data = tink_pb2.KeyData.FromString(
        self.key_manager.new_key_data(key_template))
    self.assertEqual(key_data.type_url, self.key_manager.key_type())
    self.assertEqual(key_data.key_material_type, tink_pb2.KeyData.SYMMETRIC)
    key = aes_siv_pb2.AesSivKey.FromString(key_data.value)
    self.assertEqual(key.version, 0)
    self.assertLen(key.key_value, 64)

  def test_invalid_params_raise_exception(self):
    key_template = self.new_aes_siv_key_template(65)
    with self.assertRaises(tink_bindings.PythonTinkException):
      self.key_manager.new_key_data(key_template)

  def test_encrypt_decrypt(self):
    key_template = self.new_aes_siv_key_template(64)
    key_data = self.key_manager.new_key_data(key_template)

    primitive = self.key_manager.primitive(key_data)
    plaintext = b'plaintext'
    associated_data = b'associated_data'
    ciphertext = primitive.encrypt_deterministically(plaintext, associated_data)
    self.assertEqual(
        primitive.decrypt_deterministically(ciphertext, associated_data),
        plaintext)


class HybridKeyManagerTest(absltest.TestCase):

  def hybrid_decrypt_key_manager(self):
    return tink_bindings.HybridDecryptKeyManager.from_cc_registry(
        'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPrivateKey')

  def hybrid_encrypt_key_manager(self):
    return tink_bindings.HybridEncryptKeyManager.from_cc_registry(
        'type.googleapis.com/google.crypto.tink.EciesAeadHkdfPublicKey')

  def test_new_key_data(self):
    key_manager = self.hybrid_decrypt_key_manager()
    key_data = tink_pb2.KeyData.FromString(
        key_manager.new_key_data(
            hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM
            .SerializeToString()))
    self.assertEqual(key_data.type_url, key_manager.key_type())
    self.assertEqual(key_data.key_material_type,
                     tink_pb2.KeyData.ASYMMETRIC_PRIVATE)
    key = ecies_aead_hkdf_pb2.EciesAeadHkdfPrivateKey.FromString(key_data.value)
    self.assertLen(key.key_value, 32)
    self.assertEqual(key.public_key.params.kem_params.curve_type,
                     common_pb2.NIST_P256)

  def test_new_key_data_invalid_params_raise_exception(self):
    with self.assertRaisesRegex(tink_bindings.PythonTinkException,
                                'Unsupported elliptic curve'):
      self.hybrid_decrypt_key_manager().new_key_data(
          hybrid.hybrid_key_templates.create_ecies_aead_hkdf_key_template(
              curve_type=cast(common_pb2.EllipticCurveType, 100),  # invalid
              ec_point_format=common_pb2.UNCOMPRESSED,
              hash_type=common_pb2.SHA256,
              dem_key_template=aead.aead_key_templates.AES128_GCM)
          .SerializeToString())

  def test_encrypt_decrypt(self):
    decrypt_key_manager = self.hybrid_decrypt_key_manager()
    encrypt_key_manager = self.hybrid_encrypt_key_manager()
    key_data = decrypt_key_manager.new_key_data(
        hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM
        .SerializeToString())
    public_key_data = decrypt_key_manager.public_key_data(key_data)
    hybrid_encrypt = encrypt_key_manager.primitive(public_key_data)
    ciphertext = hybrid_encrypt.encrypt(b'some plaintext', b'some context info')
    hybrid_decrypt = decrypt_key_manager.primitive(key_data)
    self.assertEqual(hybrid_decrypt.decrypt(ciphertext, b'some context info'),
                     b'some plaintext')

  def test_decrypt_fails(self):
    decrypt_key_manager = self.hybrid_decrypt_key_manager()
    key_data = decrypt_key_manager.new_key_data(
        hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM
        .SerializeToString())
    hybrid_decrypt = decrypt_key_manager.primitive(key_data)
    with self.assertRaisesRegex(tink_bindings.PythonTinkException,
                                'ciphertext too short'):
      hybrid_decrypt.decrypt(b'bad ciphertext', b'some context info')


class HpkeKeyManagerTest(parameterized.TestCase):

  def hybrid_decrypt_key_manager(self):
    return tink_bindings.HybridDecryptKeyManager.from_cc_registry(
        'type.googleapis.com/google.crypto.tink.HpkePrivateKey')

  def hybrid_encrypt_key_manager(self):
    return tink_bindings.HybridEncryptKeyManager.from_cc_registry(
        'type.googleapis.com/google.crypto.tink.HpkePublicKey')

  def test_new_key_data(self):
    key_manager = self.hybrid_decrypt_key_manager()
    key_data = tink_pb2.KeyData.FromString(
        key_manager.new_key_data(
            hybrid.hybrid_key_templates
            .DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM.SerializeToString(
            )))
    self.assertEqual(key_data.type_url, key_manager.key_type())
    self.assertEqual(key_data.key_material_type,
                     tink_pb2.KeyData.ASYMMETRIC_PRIVATE)
    key = hpke_pb2.HpkePrivateKey.FromString(key_data.value)
    self.assertLen(key.private_key, 32)  # HPKE 'Nsk' parameter length  = 32
    self.assertEqual(key.public_key.params.kem,
                     hpke_pb2.DHKEM_X25519_HKDF_SHA256)
    self.assertEqual(key.public_key.params.kdf, hpke_pb2.HKDF_SHA256)
    self.assertEqual(key.public_key.params.aead, hpke_pb2.AES_128_GCM)

  def test_new_key_data_invalid_kem_raise_exception(self):
    with self.assertRaisesRegex(tink_bindings.PythonTinkException,
                                'Invalid KEM param.'):
      self.hybrid_decrypt_key_manager().new_key_data(
          hybrid.hybrid_key_templates._create_hpke_key_template(
              hpke_kem=hpke_pb2.KEM_UNKNOWN,
              hpke_kdf=hpke_pb2.HKDF_SHA256,
              hpke_aead=hpke_pb2.AES_128_GCM,
              output_prefix_type=tink_pb2.TINK).SerializeToString())

  def test_new_key_data_invalid_kdf_raise_exception(self):
    with self.assertRaisesRegex(tink_bindings.PythonTinkException,
                                'Invalid KDF param.'):
      self.hybrid_decrypt_key_manager().new_key_data(
          hybrid.hybrid_key_templates._create_hpke_key_template(
              hpke_kem=hpke_pb2.DHKEM_X25519_HKDF_SHA256,
              hpke_kdf=hpke_pb2.KDF_UNKNOWN,
              hpke_aead=hpke_pb2.AES_128_GCM,
              output_prefix_type=tink_pb2.TINK).SerializeToString())

  def test_new_key_data_invalid_aead_raise_exception(self):
    with self.assertRaisesRegex(tink_bindings.PythonTinkException,
                                'Invalid AEAD param.'):
      self.hybrid_decrypt_key_manager().new_key_data(
          hybrid.hybrid_key_templates._create_hpke_key_template(
              hpke_kem=hpke_pb2.DHKEM_X25519_HKDF_SHA256,
              hpke_kdf=hpke_pb2.HKDF_SHA256,
              hpke_aead=hpke_pb2.AEAD_UNKNOWN,
              output_prefix_type=tink_pb2.TINK).SerializeToString())

  def test_encrypt_decrypt(self):
    decrypt_key_manager = self.hybrid_decrypt_key_manager()
    encrypt_key_manager = self.hybrid_encrypt_key_manager()
    key_data = decrypt_key_manager.new_key_data(
        hybrid.hybrid_key_templates
        .DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM.SerializeToString())
    public_key_data = decrypt_key_manager.public_key_data(key_data)
    hybrid_encrypt = encrypt_key_manager.primitive(public_key_data)
    ciphertext = hybrid_encrypt.encrypt(b'some plaintext', b'some context info')
    hybrid_decrypt = decrypt_key_manager.primitive(key_data)
    self.assertEqual(
        hybrid_decrypt.decrypt(ciphertext, b'some context info'),
        b'some plaintext')

  @parameterized.parameters(
      [tink_pb2.TINK, tink_pb2.RAW, tink_pb2.CRUNCHY, tink_pb2.LEGACY])
  def test_encrypt_decrypt_by_prefix(self, prefix):
    decrypt_key_manager = self.hybrid_decrypt_key_manager()
    encrypt_key_manager = self.hybrid_encrypt_key_manager()
    key_data = decrypt_key_manager.new_key_data(
        hybrid.hybrid_key_templates._create_hpke_key_template(
            hpke_kem=hpke_pb2.DHKEM_X25519_HKDF_SHA256,
            hpke_kdf=hpke_pb2.HKDF_SHA256,
            hpke_aead=hpke_pb2.AES_128_GCM,
            output_prefix_type=prefix).SerializeToString())
    public_key_data = decrypt_key_manager.public_key_data(key_data)
    hybrid_encrypt = encrypt_key_manager.primitive(public_key_data)
    ciphertext = hybrid_encrypt.encrypt(b'some plaintext', b'some context info')
    hybrid_decrypt = decrypt_key_manager.primitive(key_data)
    self.assertEqual(
        hybrid_decrypt.decrypt(ciphertext, b'some context info'),
        b'some plaintext')

  def test_decrypt_fails(self):
    decrypt_key_manager = self.hybrid_decrypt_key_manager()
    key_data = decrypt_key_manager.new_key_data(
        hybrid.hybrid_key_templates
        .DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM.SerializeToString())
    hybrid_decrypt = decrypt_key_manager.primitive(key_data)
    with self.assertRaisesRegex(tink_bindings.PythonTinkException,
                                'Ciphertext is too short.'):
      hybrid_decrypt.decrypt(b'bad ciphertext', b'some context info')


class MacKeyManagerTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.key_manager = tink_bindings.MacKeyManager.from_cc_registry(
        'type.googleapis.com/google.crypto.tink.HmacKey')

  def new_hmac_key_template(self, hash_type, tag_size, key_size):
    key_format = hmac_pb2.HmacKeyFormat()
    key_format.params.hash = hash_type
    key_format.params.tag_size = tag_size
    key_format.key_size = key_size
    key_template = tink_pb2.KeyTemplate()
    key_template.type_url = 'type.googleapis.com/google.crypto.tink.HmacKey'
    key_template.value = key_format.SerializeToString()
    return key_template.SerializeToString()

  def test_key_type(self):
    self.assertEqual(self.key_manager.key_type(),
                     'type.googleapis.com/google.crypto.tink.HmacKey')

  def test_new_key_data(self):
    key_template = self.new_hmac_key_template(common_pb2.SHA256, 24, 16)
    key_data = tink_pb2.KeyData.FromString(
        self.key_manager.new_key_data(key_template))
    self.assertEqual(key_data.type_url, self.key_manager.key_type())
    key = hmac_pb2.HmacKey.FromString(key_data.value)
    self.assertEqual(key.version, 0)
    self.assertEqual(key.params.hash, common_pb2.SHA256)
    self.assertEqual(key.params.tag_size, 24)
    self.assertLen(key.key_value, 16)

  def test_invalid_params_raise_exception(self):
    key_template = self.new_hmac_key_template(common_pb2.SHA256, 9, 16)
    with self.assertRaises(tink_bindings.PythonTinkException):
      self.key_manager.new_key_data(key_template)

  def test_mac_success(self):
    mac = self.key_manager.primitive(
        self.key_manager.new_key_data(
            self.new_hmac_key_template(common_pb2.SHA256, 24, 16)))
    data = b'data'
    tag = mac.compute_mac(data)
    self.assertLen(tag, 24)
    # No exception raised.
    mac.verify_mac(tag, data)

  def test_mac_wrong(self):
    mac = self.key_manager.primitive(
        self.key_manager.new_key_data(
            self.new_hmac_key_template(common_pb2.SHA256, 16, 16)))
    with self.assertRaisesRegex(tink_bindings.PythonTinkException,
                                'verification failed'):
      mac.verify_mac(b'0123456789ABCDEF', b'data')


class JwtMacKeyManagerTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.key_manager = tink_bindings.MacKeyManager.from_cc_registry(
        'type.googleapis.com/google.crypto.tink.JwtHmacKey')

  def new_jwt_hmac_key_template(self, algorithm, key_size):
    key_format = jwt_hmac_pb2.JwtHmacKeyFormat()
    key_format.algorithm = algorithm
    key_format.key_size = key_size
    key_template = tink_pb2.KeyTemplate()
    key_template.type_url = 'type.googleapis.com/google.crypto.tink.JwtHmacKey'
    key_template.value = key_format.SerializeToString()
    return key_template.SerializeToString()

  def test_key_type(self):
    self.assertEqual(self.key_manager.key_type(),
                     'type.googleapis.com/google.crypto.tink.JwtHmacKey')

  def test_new_key_data(self):
    key_template = self.new_jwt_hmac_key_template(jwt_hmac_pb2.HS256, 32)
    key_data = tink_pb2.KeyData.FromString(
        self.key_manager.new_key_data(key_template))
    self.assertEqual(key_data.type_url, self.key_manager.key_type())
    key = jwt_hmac_pb2.JwtHmacKey.FromString(key_data.value)
    self.assertEqual(key.version, 0)
    self.assertEqual(key.algorithm, jwt_hmac_pb2.HS256)
    self.assertLen(key.key_value, 32)

  def test_too_short_key_size_raises_exception(self):
    key_template = self.new_jwt_hmac_key_template(jwt_hmac_pb2.HS256, 31)
    with self.assertRaises(tink_bindings.PythonTinkException):
      self.key_manager.new_key_data(key_template)

  def test_mac_success(self):
    mac = self.key_manager.primitive(
        self.key_manager.new_key_data(
            self.new_jwt_hmac_key_template(jwt_hmac_pb2.HS256, 32)))
    data = b'data'
    tag = mac.compute_mac(data)
    self.assertLen(tag, 32)
    # No exception raised.
    mac.verify_mac(tag, data)

  def test_mac_wrong(self):
    mac = self.key_manager.primitive(
        self.key_manager.new_key_data(
            self.new_jwt_hmac_key_template(jwt_hmac_pb2.HS256, 32)))
    with self.assertRaisesRegex(tink_bindings.PythonTinkException,
                                'verification failed'):
      mac.verify_mac(b'0123456789ABCDEF0123456789ABCDEF', b'data')


class PrfKeyManagerTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.key_manager = tink_bindings.PrfKeyManager.from_cc_registry(
        'type.googleapis.com/google.crypto.tink.HmacPrfKey')

  def new_hmac_prf_key_template(self, hash_type, key_size):
    key_format = hmac_prf_pb2.HmacPrfKeyFormat()
    key_format.params.hash = hash_type
    key_format.key_size = key_size
    key_format.version = 0
    key_template = tink_pb2.KeyTemplate()
    key_template.type_url = 'type.googleapis.com/google.crypto.tink.HmacPrfKey'
    key_template.value = key_format.SerializeToString()
    return key_template.SerializeToString()

  def test_key_type(self):
    self.assertEqual(self.key_manager.key_type(),
                     'type.googleapis.com/google.crypto.tink.HmacPrfKey')

  def test_new_key_data(self):
    key_template = self.new_hmac_prf_key_template(
        hash_type=common_pb2.SHA256, key_size=16)
    key_data = tink_pb2.KeyData.FromString(
        self.key_manager.new_key_data(key_template))
    self.assertEqual(key_data.type_url, self.key_manager.key_type())
    key = hmac_pb2.HmacKey.FromString(key_data.value)
    self.assertEqual(key.version, 0)
    self.assertEqual(key.params.hash, common_pb2.SHA256)
    self.assertLen(key.key_value, 16)

  def test_invalid_params_raise_exception(self):
    key_template = self.new_hmac_prf_key_template(
        hash_type=common_pb2.SHA256, key_size=7)
    with self.assertRaises(tink_bindings.PythonTinkException):
      self.key_manager.new_key_data(key_template)

  def test_prf_success(self):
    prf = self.key_manager.primitive(
        self.key_manager.new_key_data(
            self.new_hmac_prf_key_template(
                hash_type=common_pb2.SHA256, key_size=16)))
    output = prf.compute(b'input_data', output_length=31)
    self.assertLen(output, 31)
    self.assertEqual(prf.compute(b'input_data', output_length=31), output)

  def test_prf_bad_output_length(self):
    prf = self.key_manager.primitive(
        self.key_manager.new_key_data(
            self.new_hmac_prf_key_template(
                hash_type=common_pb2.SHA256, key_size=16)))
    with self.assertRaises(tink_bindings.PythonTinkException):
      _ = prf.compute(b'input_data', output_length=12345)


class PublicKeySignVerifyKeyManagerTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    public_key_verify_manager = tink_bindings.PublicKeyVerifyKeyManager
    self.key_manager_verify = public_key_verify_manager.from_cc_registry(
        'type.googleapis.com/google.crypto.tink.EcdsaPublicKey')
    public_key_sign_manager = tink_bindings.PublicKeySignKeyManager
    self.key_manager_sign = public_key_sign_manager.from_cc_registry(
        'type.googleapis.com/google.crypto.tink.EcdsaPrivateKey')

  def new_ecdsa_key_template(self, hash_type, curve_type, encoding,
                             public=False):
    params = ecdsa_pb2.EcdsaParams(
        hash_type=hash_type, curve=curve_type, encoding=encoding)
    key_format = ecdsa_pb2.EcdsaKeyFormat(params=params)
    key_template = tink_pb2.KeyTemplate()
    if public:
      append = 'EcdsaPublicKey'
    else:
      append = 'EcdsaPrivateKey'
    key_template.type_url = 'type.googleapis.com/google.crypto.tink.' + append

    key_template.value = key_format.SerializeToString()
    return key_template.SerializeToString()

  def test_key_type_sign(self):
    self.assertEqual(self.key_manager_sign.key_type(),
                     'type.googleapis.com/google.crypto.tink.EcdsaPrivateKey')

  def test_key_type_verify(self):
    self.assertEqual(self.key_manager_verify.key_type(),
                     'type.googleapis.com/google.crypto.tink.EcdsaPublicKey')

  def test_new_key_data_sign(self):
    key_template = self.new_ecdsa_key_template(
        common_pb2.SHA256, common_pb2.NIST_P256, ecdsa_pb2.DER)
    key_data = tink_pb2.KeyData.FromString(
        self.key_manager_sign.new_key_data(key_template))
    self.assertEqual(key_data.type_url, self.key_manager_sign.key_type())
    key = ecdsa_pb2.EcdsaPrivateKey.FromString(key_data.value)
    public_key = key.public_key
    self.assertEqual(key.version, 0)
    self.assertEqual(public_key.version, 0)
    self.assertEqual(public_key.params.hash_type, common_pb2.SHA256)
    self.assertEqual(public_key.params.curve, common_pb2.NIST_P256)
    self.assertEqual(public_key.params.encoding, ecdsa_pb2.DER)
    self.assertLen(key.key_value, 32)

  def test_new_key_data_verify(self):
    key_template = self.new_ecdsa_key_template(
        common_pb2.SHA256, common_pb2.NIST_P256, ecdsa_pb2.DER, True)
    with self.assertRaisesRegex(tink_bindings.PythonTinkException,
                                'not supported'):
      self.key_manager_verify.new_key_data(key_template)

  def test_signature_success(self):
    priv_key = self.key_manager_sign.new_key_data(
        self.new_ecdsa_key_template(common_pb2.SHA256, common_pb2.NIST_P256,
                                    ecdsa_pb2.DER))
    pub_key = self.key_manager_sign.public_key_data(priv_key)

    verifier = self.key_manager_verify.primitive(pub_key)
    signer = self.key_manager_sign.primitive(priv_key)

    data = b'data'
    signature = signer.sign(data)

    # Starts with a DER sequence
    self.assertEqual(bytearray(signature)[0], 0x30)

    verifier.verify(signature, data)

  def test_signature_fails(self):
    key_template = self.new_ecdsa_key_template(
        common_pb2.SHA256, common_pb2.NIST_P256, ecdsa_pb2.DER, False)
    priv_key = self.key_manager_sign.new_key_data(key_template)
    pub_key = self.key_manager_sign.public_key_data(priv_key)

    signer = self.key_manager_sign.primitive(priv_key)
    verifier = self.key_manager_verify.primitive(pub_key)

    data = b'data'
    signature = signer.sign(data)

    with self.assertRaisesRegex(tink_bindings.PythonTinkException,
                                'Signature is not valid'):
      verifier.verify(signature, b'wrongdata')

    with self.assertRaisesRegex(tink_bindings.PythonTinkException,
                                'Signature is not valid'):
      verifier.verify(b'wrongsignature', data)


class JwtPublicKeySignVerifyKeyManagerTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    public_key_verify_manager = tink_bindings.PublicKeyVerifyKeyManager
    self.key_manager_verify = public_key_verify_manager.from_cc_registry(
        'type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey')
    public_key_sign_manager = tink_bindings.PublicKeySignKeyManager
    self.key_manager_sign = public_key_sign_manager.from_cc_registry(
        'type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey')

  def test_new_key_data_verify_fails(self):
    key_format = jwt_ecdsa_pb2.JwtEcdsaKeyFormat(algorithm=jwt_ecdsa_pb2.ES256)
    key_template = tink_pb2.KeyTemplate()
    key_template.type_url = (
        'type.googleapis.com/google.crypto.tink.JwtEcdsaPublicKey')
    key_template.value = key_format.SerializeToString()
    with self.assertRaisesRegex(tink_bindings.PythonTinkException,
                                'not supported'):
      self.key_manager_verify.new_key_data(key_template.SerializeToString())

  def test_signature_success(self):
    key_format = jwt_ecdsa_pb2.JwtEcdsaKeyFormat(algorithm=jwt_ecdsa_pb2.ES256)
    key_template = tink_pb2.KeyTemplate()
    key_template.type_url = (
        'type.googleapis.com/google.crypto.tink.JwtEcdsaPrivateKey')
    key_template.value = key_format.SerializeToString()

    priv_key = self.key_manager_sign.new_key_data(
        key_template.SerializeToString())
    pub_key = self.key_manager_sign.public_key_data(priv_key)

    verifier = self.key_manager_verify.primitive(pub_key)
    signer = self.key_manager_sign.primitive(priv_key)

    data = b'data'
    signature = signer.sign(data)
    verifier.verify(signature, data)

    with self.assertRaises(tink_bindings.PythonTinkException):
      verifier.verify(signature, b'wrongdata')

    with self.assertRaises(tink_bindings.PythonTinkException):
      verifier.verify(b'wrongsignature', data)


if __name__ == '__main__':
  absltest.main()
