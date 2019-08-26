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

"""Tests for tink.python.public_key_verify_key_manager."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

from absl.testing import absltest

from tink.proto import common_pb2
from tink.proto import ecdsa_pb2
from tink.proto import tink_pb2
from tink.python import tink_config
from tink.python.core import tink_error
from tink.python.signature import public_key_sign_key_manager
from tink.python.signature import public_key_verify_key_manager


def setUpModule():
  tink_config.register()


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


class PublicKeyVerifyKeyManagerTest(absltest.TestCase):

  def setUp(self):
    super(PublicKeyVerifyKeyManagerTest, self).setUp()
    self.key_manager = public_key_verify_key_manager.from_cc_registry(
        'type.googleapis.com/google.crypto.tink.EcdsaPublicKey')
    self.key_manager_sign = public_key_sign_key_manager.from_cc_registry(
        'type.googleapis.com/google.crypto.tink.EcdsaPrivateKey')

  def test_key_type(self):
    self.assertEqual(self.key_manager.key_type(),
                     'type.googleapis.com/google.crypto.tink.EcdsaPublicKey')

  def test_new_key_data(self):
    key_template = new_ecdsa_key_template(
        common_pb2.SHA256, common_pb2.NIST_P256, ecdsa_pb2.DER, True)
    with self.assertRaisesRegex(tink_error.TinkError, 'not supported'):
      self.key_manager.new_key_data(key_template)

  def test_verify_success(self):
    key_template = new_ecdsa_key_template(
        common_pb2.SHA256, common_pb2.NIST_P256, ecdsa_pb2.DER, False)
    priv_key = self.key_manager_sign.new_key_data(key_template)
    pub_key = self.key_manager_sign.public_key_data(priv_key)

    signer = self.key_manager_sign.primitive(priv_key)
    verifier = self.key_manager.primitive(pub_key)

    data = b'data'
    signature = signer.sign(data)

    verifier.verify(signature, data)

  def test_verify_wrong(self):
    key_template = new_ecdsa_key_template(
        common_pb2.SHA256, common_pb2.NIST_P256, ecdsa_pb2.DER, False)
    priv_key = self.key_manager_sign.new_key_data(key_template)
    pub_key = self.key_manager_sign.public_key_data(priv_key)

    signer = self.key_manager_sign.primitive(priv_key)
    verifier = self.key_manager.primitive(pub_key)

    data = b'data'
    signature = signer.sign(data)

    with self.assertRaisesRegex(tink_error.TinkError, 'Signature is not valid'):
      verifier.verify(signature, 'wrongdata')

    with self.assertRaisesRegex(tink_error.TinkError, 'Signature is not valid'):
      verifier.verify('wrongsignature', data)


if __name__ == '__main__':
  absltest.main()
