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

"""Tests for tink.python.public_key_sign_key_manager."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from absl.testing import absltest

from tink.proto import common_pb2
from tink.proto import ecdsa_pb2
from tink.proto import tink_pb2
from tink.python import tink_config
from tink.python.signature import public_key_sign
from tink.python.signature import public_key_sign_key_manager
from tink.python.signature import public_key_verify_key_manager


def setUpModule():
  tink_config.register()


def new_ecdsa_key_template(hash_type, curve_type, encoding):
  key_format = ecdsa_pb2.EcdsaKeyFormat()
  key_format.params.hash_type = hash_type
  key_format.params.curve = curve_type
  key_format.params.encoding = encoding
  key_template = tink_pb2.KeyTemplate()
  key_template.type_url = (
      'type.googleapis.com/google.crypto.tink.EcdsaPrivateKey')
  key_template.value = key_format.SerializeToString()
  return key_template


class PublicKeySignKeyManagerTest(absltest.TestCase):

  def setUp(self):
    super(PublicKeySignKeyManagerTest, self).setUp()
    self.key_manager = public_key_sign_key_manager.from_cc_registry(
        'type.googleapis.com/google.crypto.tink.EcdsaPrivateKey')
    self.key_manager_verify = public_key_verify_key_manager.from_cc_registry(
        'type.googleapis.com/google.crypto.tink.EcdsaPublicKey')

  def test_primitive_class(self):
    self.assertEqual(self.key_manager.primitive_class(),
                     public_key_sign.PublicKeySign)

  def test_key_type(self):
    self.assertEqual(self.key_manager.key_type(),
                     'type.googleapis.com/google.crypto.tink.EcdsaPrivateKey')

  def test_new_key_data(self):
    key_template = new_ecdsa_key_template(common_pb2.SHA256,
                                          common_pb2.NIST_P256, ecdsa_pb2.DER)
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
        new_ecdsa_key_template(common_pb2.SHA256, common_pb2.NIST_P256,
                               ecdsa_pb2.DER))
    pub_key = self.key_manager.public_key_data(priv_key)

    verifier = self.key_manager_verify.primitive(pub_key)
    signer = self.key_manager.primitive(priv_key)

    data = b'data'
    signature = signer.sign(data)

    # Starts with a DER sequence
    self.assertEqual(bytearray(signature)[0], 0x30)

    verifier.verify(signature, data)


if __name__ == '__main__':
  absltest.main()
