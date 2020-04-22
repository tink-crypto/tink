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

"""Tests for tink.python.tink.signature_key_templates."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from absl.testing import absltest
from absl.testing import parameterized

from tink.proto import common_pb2
from tink.proto import ecdsa_pb2
from tink.proto import rsa_ssa_pkcs1_pb2
from tink.proto import rsa_ssa_pss_pb2
from tink.proto import tink_pb2
from tink import core
from tink import signature


ECDSA_DER_PARAMS_P256 = [
    signature.signature_key_templates.ECDSA_P256, common_pb2.SHA256,
    common_pb2.NIST_P256
]
ECDSA_DER_PARAMS_P384 = [
    signature.signature_key_templates.ECDSA_P384, common_pb2.SHA512,
    common_pb2.NIST_P384
]
ECDSA_DER_PARAMS_P521 = [
    signature.signature_key_templates.ECDSA_P521, common_pb2.SHA512,
    common_pb2.NIST_P521
]

ECDSA_IEEE_PARAMS_P256 = [
    signature.signature_key_templates.ECDSA_P256_IEEE_P1363, common_pb2.SHA256,
    common_pb2.NIST_P256
]
ECDSA_IEEE_PARAMS_P384 = [
    signature.signature_key_templates.ECDSA_P384_IEEE_P1363, common_pb2.SHA512,
    common_pb2.NIST_P384
]
ECDSA_IEEE_PARAMS_P521 = [
    signature.signature_key_templates.ECDSA_P521_IEEE_P1363, common_pb2.SHA512,
    common_pb2.NIST_P521
]

RSA_PKCS1_PARAMS_3072 = [
    signature.signature_key_templates.RSA_SSA_PKCS1_3072_SHA256_F4,
    common_pb2.SHA256, 3072, 65537
]
RSA_PKCS1_PARAMS_4096 = [
    signature.signature_key_templates.RSA_SSA_PKCS1_4096_SHA512_F4,
    common_pb2.SHA512, 4096, 65537
]

RSA_PSS_PARAMS_3072 = [
    signature.signature_key_templates.RSA_SSA_PSS_3072_SHA256_SHA256_32_F4,
    common_pb2.SHA256, 3072, 65537
]
RSA_PSS_PARAMS_4096 = [
    signature.signature_key_templates.RSA_SSA_PSS_4096_SHA512_SHA512_64_F4,
    common_pb2.SHA512, 4096, 65537
]


def bytes_to_num(data):
  res = 0

  for b in bytearray(data):
    res <<= 8
    res |= b

  return res


def setUpModule():
  signature.register()


class SignatureKeyTemplatesTest(parameterized.TestCase):

  def test_bytes_to_num(self):
    for i in range(100000):
      res = bytes_to_num(signature.signature_key_templates._num_to_bytes(i))
      self.assertEqual(res, i)

  @parameterized.named_parameters(('0', 0, b'\x00'), ('256', 256, b'\x01\x00'),
                                  ('65537', 65537, b'\x01\x00\x01'))
  def test_num_to_bytes(self, number, expected):
    self.assertEqual(signature.signature_key_templates._num_to_bytes(number),
                     expected)

    with self.assertRaises(OverflowError):
      signature.signature_key_templates._num_to_bytes(-1)

  @parameterized.named_parameters(
      ['ecdsa_p256'] + ECDSA_DER_PARAMS_P256,
      ['ecdsa_p384'] + ECDSA_DER_PARAMS_P384,
      ['ecdsa_p521'] + ECDSA_DER_PARAMS_P521,
  )
  def test_ecdsa_der(self, key_template, hash_type, curve):
    self.assertEqual(key_template.type_url,
                     'type.googleapis.com/google.crypto.tink.EcdsaPrivateKey')
    self.assertEqual(key_template.output_prefix_type, tink_pb2.TINK)

    key_format = ecdsa_pb2.EcdsaKeyFormat()
    key_format.ParseFromString(key_template.value)
    self.assertEqual(key_format.params.hash_type, hash_type)
    self.assertEqual(key_format.params.curve, curve)
    self.assertEqual(key_format.params.encoding, ecdsa_pb2.DER)

    # Check that the template works with the key manager
    key_manager = core.Registry.key_manager(key_template.type_url)
    key_manager.new_key_data(key_template)

  @parameterized.named_parameters(
      ['ecdsa_p256'] + ECDSA_IEEE_PARAMS_P256,
      ['ecdsa_p384'] + ECDSA_IEEE_PARAMS_P384,
      ['ecdsa_p521'] + ECDSA_IEEE_PARAMS_P521,
  )
  def test_ecdsa_ieee(self, key_template, hash_type, curve):
    self.assertEqual(key_template.type_url,
                     'type.googleapis.com/google.crypto.tink.EcdsaPrivateKey')
    self.assertEqual(key_template.output_prefix_type, tink_pb2.TINK)

    key_format = ecdsa_pb2.EcdsaKeyFormat()
    key_format.ParseFromString(key_template.value)
    self.assertEqual(key_format.params.hash_type, hash_type)
    self.assertEqual(key_format.params.curve, curve)
    self.assertEqual(key_format.params.encoding, ecdsa_pb2.IEEE_P1363)

    # Check that the template works with the key manager
    key_manager = core.Registry.key_manager(
        key_template.type_url)
    key_manager.new_key_data(key_template)

  def test_ed25519(self):
    key_template = signature.signature_key_templates.ED25519
    self.assertEqual(
        key_template.type_url,
        'type.googleapis.com/google.crypto.tink.Ed25519PrivateKey')
    self.assertEqual(key_template.output_prefix_type, tink_pb2.TINK)

    # Check that the template works with the key manager
    key_manager = core.Registry.key_manager(key_template.type_url)
    key_manager.new_key_data(key_template)

  @parameterized.named_parameters(
      ['rsa_pkcs1_3072'] + RSA_PKCS1_PARAMS_3072,
      ['rsa_pkcs1_4096'] + RSA_PKCS1_PARAMS_4096,
  )
  def test_rsa_pkcs1(self, key_template, hash_algo, modulus_size, exponent):
    self.assertEqual(
        key_template.type_url,
        'type.googleapis.com/google.crypto.tink.RsaSsaPkcs1PrivateKey')
    self.assertEqual(key_template.output_prefix_type, tink_pb2.TINK)

    key_format = rsa_ssa_pkcs1_pb2.RsaSsaPkcs1KeyFormat()
    key_format.ParseFromString(key_template.value)
    self.assertEqual(key_format.modulus_size_in_bits, modulus_size)
    self.assertEqual(key_format.params.hash_type, hash_algo)
    self.assertEqual(bytes_to_num(key_format.public_exponent), exponent)

    # Check that the template works with the key manager
    key_manager = core.Registry.key_manager(key_template.type_url)
    key_manager.new_key_data(key_template)

  @parameterized.named_parameters(
      ['rsa_pss_3072'] + RSA_PSS_PARAMS_3072,
      ['rsa_pss_4096'] + RSA_PSS_PARAMS_4096,
  )
  def test_rsa_pss(self, key_template, hash_algo, modulus_size, exponent):
    self.assertEqual(
        key_template.type_url,
        'type.googleapis.com/google.crypto.tink.RsaSsaPssPrivateKey')
    self.assertEqual(key_template.output_prefix_type, tink_pb2.TINK)

    key_format = rsa_ssa_pss_pb2.RsaSsaPssKeyFormat()
    key_format.ParseFromString(key_template.value)
    self.assertEqual(key_format.modulus_size_in_bits, modulus_size)
    self.assertEqual(key_format.params.sig_hash, hash_algo)
    self.assertEqual(key_format.params.mgf1_hash, hash_algo)
    self.assertEqual(bytes_to_num(key_format.public_exponent), exponent)

    # Check that the template works with the key manager
    key_manager = core.Registry.key_manager(key_template.type_url)
    key_manager.new_key_data(key_template)


if __name__ == '__main__':
  absltest.main()
