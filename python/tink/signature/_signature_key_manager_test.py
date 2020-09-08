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
"""Tests for tink.python.tink._signature_key_manager."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from absl.testing import absltest
from absl.testing import parameterized

from tink.proto import common_pb2
from tink.proto import ecdsa_pb2
from tink.proto import tink_pb2
import tink
from tink import core
from tink import signature


def setUpModule():
  signature.register()


class PublicKeySignKeyManagerTest(parameterized.TestCase):

  def test_new_key_data_ecdsa(self):
    template = signature.signature_key_templates.create_ecdsa_key_template(
        common_pb2.SHA256, common_pb2.NIST_P256, ecdsa_pb2.DER)
    key_manager = core.Registry.key_manager(template.type_url)
    key_data = key_manager.new_key_data(template)
    self.assertEqual(key_data.type_url, template.type_url)
    key = ecdsa_pb2.EcdsaPrivateKey()
    key.ParseFromString(key_data.value)
    public_key = key.public_key
    self.assertEqual(key.version, 0)
    self.assertEqual(public_key.version, 0)
    self.assertEqual(public_key.params.hash_type, common_pb2.SHA256)
    self.assertEqual(public_key.params.curve, common_pb2.NIST_P256)
    self.assertEqual(public_key.params.encoding, ecdsa_pb2.DER)
    self.assertLen(key.key_value, 32)

  def test_new_public_keyset_handle_fails(self):
    params = ecdsa_pb2.EcdsaParams(
        hash_type=common_pb2.SHA256,
        curve=common_pb2.NIST_P256,
        encoding=ecdsa_pb2.DER)
    key_format = ecdsa_pb2.EcdsaKeyFormat(params=params)
    template = tink_pb2.KeyTemplate()
    template.type_url = 'type.googleapis.com/google.crypto.tink.EcdsaPublicKey'
    template.value = key_format.SerializeToString()
    with self.assertRaises(core.TinkError):
      tink.new_keyset_handle(template)

  @parameterized.parameters([
      signature.signature_key_templates.ECDSA_P256,
      signature.signature_key_templates.ECDSA_P384,
      signature.signature_key_templates.ECDSA_P384_SHA384,
      signature.signature_key_templates.ECDSA_P521,
      signature.signature_key_templates.ECDSA_P256_IEEE_P1363,
      signature.signature_key_templates.ECDSA_P384_IEEE_P1363,
      signature.signature_key_templates.ECDSA_P384_SHA384_IEEE_P1363,
      signature.signature_key_templates.ECDSA_P521_IEEE_P1363,
      signature.signature_key_templates.ED25519,
      signature.signature_key_templates.RSA_SSA_PKCS1_3072_SHA256_F4,
      signature.signature_key_templates.RSA_SSA_PKCS1_4096_SHA512_F4,
      signature.signature_key_templates.RSA_SSA_PSS_3072_SHA256_SHA256_32_F4,
      signature.signature_key_templates.RSA_SSA_PSS_4096_SHA512_SHA512_64_F4,
  ])
  def test_sign_verify_success(self, template):
    private_handle = tink.new_keyset_handle(template)
    public_handle = private_handle.public_keyset_handle()
    verifier = public_handle.primitive(signature.PublicKeyVerify)
    signer = private_handle.primitive(signature.PublicKeySign)

    data = b'data'
    data_signature = signer.sign(data)
    verifier.verify(data_signature, data)

  @parameterized.parameters([
      signature.signature_key_templates.ECDSA_P256,
      signature.signature_key_templates.ECDSA_P384,
      signature.signature_key_templates.ECDSA_P384_SHA384,
      signature.signature_key_templates.ECDSA_P521,
      signature.signature_key_templates.ECDSA_P256_IEEE_P1363,
      signature.signature_key_templates.ECDSA_P384_IEEE_P1363,
      signature.signature_key_templates.ECDSA_P384_SHA384_IEEE_P1363,
      signature.signature_key_templates.ECDSA_P521_IEEE_P1363,
      signature.signature_key_templates.ED25519,
      signature.signature_key_templates.RSA_SSA_PKCS1_3072_SHA256_F4,
      signature.signature_key_templates.RSA_SSA_PKCS1_4096_SHA512_F4,
      signature.signature_key_templates.RSA_SSA_PSS_3072_SHA256_SHA256_32_F4,
      signature.signature_key_templates.RSA_SSA_PSS_4096_SHA512_SHA512_64_F4,
  ])
  def test_verify_wrong_fails(self, template):
    private_handle = tink.new_keyset_handle(template)
    public_handle = private_handle.public_keyset_handle()
    verifier = public_handle.primitive(signature.PublicKeyVerify)
    signer = private_handle.primitive(signature.PublicKeySign)

    with self.assertRaises(core.TinkError):
      verifier.verify(signer.sign(b'data'), b'wrongdata')

    with self.assertRaises(core.TinkError):
      verifier.verify(b'wrongsignature', b'data')


if __name__ == '__main__':
  absltest.main()
