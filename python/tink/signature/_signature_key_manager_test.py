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
from __future__ import print_function

from absl.testing import absltest

from tink.proto import common_pb2
from tink.proto import ecdsa_pb2
from tink.proto import tink_pb2
from tink import core
from tink import signature


def setUpModule():
  signature.register()


def new_ecdsa_key_template(hash_type, curve_type, encoding, public=True):
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
  return key_template


class PublicKeySignKeyManagerTest(absltest.TestCase):

  def setUp(self):
    super(PublicKeySignKeyManagerTest, self).setUp()
    self.key_manager = core.Registry.key_manager(
        'type.googleapis.com/google.crypto.tink.EcdsaPrivateKey')
    self.key_manager_verify = core.Registry.key_manager(
        'type.googleapis.com/google.crypto.tink.EcdsaPublicKey')

  def test_primitive_class(self):
    self.assertEqual(self.key_manager.primitive_class(),
                     signature.PublicKeySign)

  def test_key_type(self):
    self.assertEqual(self.key_manager.key_type(),
                     'type.googleapis.com/google.crypto.tink.EcdsaPrivateKey')

  def test_new_key_data(self):
    key_template = new_ecdsa_key_template(
        common_pb2.SHA256, common_pb2.NIST_P256, ecdsa_pb2.DER, public=False)
    key_data = self.key_manager.new_key_data(key_template)
    self.assertEqual(key_data.type_url, self.key_manager.key_type())
    key = ecdsa_pb2.EcdsaPrivateKey()
    key.ParseFromString(key_data.value)
    public_key = key.public_key
    self.assertEqual(key.version, 0)
    self.assertEqual(public_key.version, 0)
    self.assertEqual(public_key.params.hash_type, common_pb2.SHA256)
    self.assertEqual(public_key.params.curve, common_pb2.NIST_P256)
    self.assertEqual(public_key.params.encoding, ecdsa_pb2.DER)
    self.assertLen(key.key_value, 32)

  def test_signature_success(self):

    priv_key = self.key_manager.new_key_data(
        new_ecdsa_key_template(
            common_pb2.SHA256,
            common_pb2.NIST_P256,
            ecdsa_pb2.DER,
            public=False))
    pub_key = self.key_manager.public_key_data(priv_key)

    verifier = self.key_manager_verify.primitive(pub_key)
    signer = self.key_manager.primitive(priv_key)

    data = b'data'
    data_signature = signer.sign(data)

    # Starts with a DER sequence
    self.assertEqual(bytearray(data_signature)[0], 0x30)

    verifier.verify(data_signature, data)


class PublicKeyVerifyKeyManagerTest(absltest.TestCase):

  def setUp(self):
    super(PublicKeyVerifyKeyManagerTest, self).setUp()
    self.key_manager = core.Registry.key_manager(
        'type.googleapis.com/google.crypto.tink.EcdsaPublicKey')
    self.key_manager_sign = core.Registry.key_manager(
        'type.googleapis.com/google.crypto.tink.EcdsaPrivateKey')

  def test_key_type(self):
    self.assertEqual(self.key_manager.key_type(),
                     'type.googleapis.com/google.crypto.tink.EcdsaPublicKey')

  def test_new_key_data(self):
    key_template = new_ecdsa_key_template(
        common_pb2.SHA256, common_pb2.NIST_P256, ecdsa_pb2.DER, public=True)
    with self.assertRaisesRegex(core.TinkError, 'not supported'):
      self.key_manager.new_key_data(key_template)

  def test_verify_success(self):
    key_template = new_ecdsa_key_template(
        common_pb2.SHA256, common_pb2.NIST_P256, ecdsa_pb2.DER, public=False)
    priv_key = self.key_manager_sign.new_key_data(key_template)
    pub_key = self.key_manager_sign.public_key_data(priv_key)

    signer = self.key_manager_sign.primitive(priv_key)
    verifier = self.key_manager.primitive(pub_key)

    data = b'data'
    verifier.verify(signer.sign(data), data)

  def test_verify_wrong(self):
    key_template = new_ecdsa_key_template(
        common_pb2.SHA256, common_pb2.NIST_P256, ecdsa_pb2.DER, public=False)
    priv_key = self.key_manager_sign.new_key_data(key_template)
    pub_key = self.key_manager_sign.public_key_data(priv_key)

    signer = self.key_manager_sign.primitive(priv_key)
    verifier = self.key_manager.primitive(pub_key)

    data = b'data'
    with self.assertRaisesRegex(core.TinkError, 'Signature is not valid'):
      verifier.verify(signer.sign(data), b'wrongdata')

    with self.assertRaisesRegex(core.TinkError, 'Signature is not valid'):
      verifier.verify(b'wrongsignature', data)


if __name__ == '__main__':
  absltest.main()
