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
"""Tests for tink.python.tink.integration.aws_kms_aead."""

import os

from absl.testing import absltest

import tink
from tink import aead
from tink.aead import _kms_aead_key_manager
from tink.integration import awskms
from tink.testing import helper

CREDENTIAL_PATH = os.path.join(helper.tink_py_testdata_path(),
                               'aws/credentials.ini')
BAD_CREDENTIALS_PATH = os.path.join(helper.tink_py_testdata_path(),
                                    'aws/credentials_bad.ini')
KEY_URI = ('aws-kms://arn:aws:kms:us-east-2:235739564943:key/'
           '3ee50705-5a82-4f5b-9753-05c4f473922f')
KEY_URI_2 = ('aws-kms://arn:aws:kms:us-east-2:235739564943:key/'
             'b3ca2efd-a8fb-47f2-b541-7e20f8c5cd11')
GCP_KEY_URI = ('gcp-kms://projects/tink-test-infrastructure/locations/global/'
               'keyRings/unit-and-integration-testing/cryptoKeys/aead-key')


def setUpModule():
  aead.register()


class AwsKmsAeadTest(absltest.TestCase):

  def tearDown(self):
    super().tearDown()
    _kms_aead_key_manager.reset_kms_clients()

  def test_encrypt_decrypt(self):
    aws_client = awskms.AwsKmsClient(KEY_URI, CREDENTIAL_PATH)
    aws_aead = aws_client.get_aead(KEY_URI)

    plaintext = b'hello'
    associated_data = b'world'
    ciphertext = aws_aead.encrypt(plaintext, associated_data)
    self.assertEqual(plaintext, aws_aead.decrypt(ciphertext, associated_data))

    plaintext = b'hello'
    ciphertext = aws_aead.encrypt(plaintext, b'')
    self.assertEqual(plaintext, aws_aead.decrypt(ciphertext, b''))

  def test_corrupted_ciphertext(self):
    aws_client = awskms.AwsKmsClient(KEY_URI, CREDENTIAL_PATH)
    aws_aead = aws_client.get_aead(KEY_URI)

    plaintext = b'helloworld'
    ciphertext = aws_aead.encrypt(plaintext, b'')
    self.assertEqual(plaintext, aws_aead.decrypt(ciphertext, b''))

    # Corrupt each byte once and check that decryption fails
    # NOTE: Skipping two bytes as they are malleable
    for byte_idx in [b for b in range(len(ciphertext)) if b not in [77, 123]]:
      tmp_ciphertext = list(ciphertext)
      tmp_ciphertext[byte_idx] ^= 1
      corrupted_ciphertext = bytes(tmp_ciphertext)
      with self.assertRaises(tink.TinkError):
        aws_aead.decrypt(corrupted_ciphertext, b'')

  def test_encrypt_with_bad_uri(self):
    with self.assertRaises(tink.TinkError):
      aws_client = awskms.AwsKmsClient(KEY_URI, CREDENTIAL_PATH)
      aws_client.get_aead(GCP_KEY_URI)

  def test_encrypt_with_bad_credentials(self):
    aws_client = awskms.AwsKmsClient(KEY_URI, BAD_CREDENTIALS_PATH)
    aws_aead = aws_client.get_aead(KEY_URI)

    plaintext = b'hello'
    associated_data = b'world'
    with self.assertRaises(tink.TinkError):
      aws_aead.encrypt(plaintext, associated_data)

  def test_client_registration(self):
    # Register AWS KMS Client bound to KEY_URI.
    awskms.AwsKmsClient.register_client(KEY_URI, CREDENTIAL_PATH)

    # Create a keyset handle for KEY_URI and use it.
    handle = tink.new_keyset_handle(
        aead.aead_key_templates.create_kms_aead_key_template(KEY_URI)
    )
    aws_aead = handle.primitive(aead.Aead)
    ciphertext = aws_aead.encrypt(b'plaintext', b'associated_data')
    self.assertEqual(
        b'plaintext', aws_aead.decrypt(ciphertext, b'associated_data')
    )

    # It fails for any other key URI.
    with self.assertRaises(tink.TinkError):
      handle2 = tink.new_keyset_handle(
          aead.aead_key_templates.create_kms_aead_key_template(KEY_URI_2)
      )
      gcp_aead = handle2.primitive(aead.Aead)
      gcp_aead.encrypt(b'plaintext', b'associated_data')


if __name__ == '__main__':
  absltest.main()
