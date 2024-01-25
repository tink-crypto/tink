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

"""Tests for tink.python.tink.integration.gcp_kms_client."""

import os

from absl.testing import absltest
from absl.testing import parameterized
from google.api_core import exceptions as core_exceptions
from google.cloud import kms_v1

from tink import core
from tink.integration import gcpkms
from tink.testing import helper


KEY_URI1 = 'gcp-kms://projects/p1/locations/global/keyRings/kr1/cryptoKeys/ck1'
KEY_URI2 = 'gcp-kms://projects/p1/locations/global/keyRings/kr1/cryptoKeys/ck2'
AWS_KEY_URI = 'aws-kms://arn:aws:kms:us-west-2:acc:other/key3'
PLAINTEXT = b'plaintext'
CIPHERTEXT = b'ciphertext'
ASSOCIATED_DATA = b'associated_data'
CREDENTIAL_PATH = os.path.join(
    helper.tink_py_testdata_path(), 'gcp/credential.json'
)


class CustomException(core_exceptions.GoogleAPIError):
  pass


class GcpKmsClientTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    absltest.mock.patch.object(kms_v1, 'KeyManagementServiceClient').start()

  def tearDown(self):
    absltest.mock.patch.stopall()
    super().tearDown()

  @parameterized.parameters(
      (KEY_URI1, True),
      (KEY_URI2, False),
      (KEY_URI1 + 'suffix', False),
      (AWS_KEY_URI, False),
  )
  def test_client_bound_to_key_uri(self, key_uri, expected_support):
    gcp_client = gcpkms.GcpKmsClient(KEY_URI1, CREDENTIAL_PATH)
    self.assertEqual(gcp_client.does_support(key_uri), expected_support)

  @parameterized.parameters(
      (KEY_URI1, True),
      (KEY_URI2, True),
      (KEY_URI1 + 'suffix', True),
      (AWS_KEY_URI, False),
  )
  def test_client_not_bound_to_key_uri(self, key_uri, expected_support):
    gcp_client = gcpkms.GcpKmsClient(None, CREDENTIAL_PATH)
    self.assertEqual(gcp_client.does_support(key_uri), expected_support)

  @parameterized.parameters(
      (KEY_URI1, True),
      (KEY_URI2, True),
      (AWS_KEY_URI, False),
  )
  def test_client_empty_key_uri(self, key_uri, expected_support):
    gcp_client = gcpkms.GcpKmsClient('', CREDENTIAL_PATH)
    self.assertEqual(gcp_client.does_support(key_uri), expected_support)

  def test_client_invalid_path(self):
    with self.assertRaises(FileNotFoundError):
      gcpkms.GcpKmsClient(None, CREDENTIAL_PATH + 'corrupted')

  @parameterized.parameters(
      '',
      AWS_KEY_URI,
      KEY_URI1 + '/',
      KEY_URI1 + '/cryptoKeyVersions/1',
      'projects/p1/locations/global/keyRings/kr1/cryptoKeys/ck1',
      'gcp-kms:/projects/p1/locations/global/keyRings/kr1/cryptoKeys/ck1',
  )
  def test_aead_wrong_key_uri_fails(self, key_uri):
    gcp_client = gcpkms.GcpKmsClient(None, CREDENTIAL_PATH)
    with self.assertRaises(core.TinkError):
      gcp_client.get_aead(key_uri)

  def test_aead_different_key_uri_fails(self):
    gcp_client = gcpkms.GcpKmsClient(KEY_URI1, CREDENTIAL_PATH)
    with self.assertRaises(core.TinkError):
      gcp_client.get_aead(KEY_URI1 + 'suffix')

  def test_aead_encryption_fails(self):
    kms_v1.KeyManagementServiceClient().encrypt.side_effect = CustomException()
    gcp_client = gcpkms.GcpKmsClient(KEY_URI1, CREDENTIAL_PATH)
    gcp_aead = gcp_client.get_aead(KEY_URI1)
    with self.assertRaises(core.TinkError):
      gcp_aead.encrypt(CIPHERTEXT, ASSOCIATED_DATA)

  def test_aead_decryption_fails(self):
    kms_v1.KeyManagementServiceClient().decrypt.side_effect = CustomException()
    gcp_client = gcpkms.GcpKmsClient(KEY_URI1, CREDENTIAL_PATH)
    gcp_aead = gcp_client.get_aead(KEY_URI1)
    with self.assertRaises(core.TinkError):
      gcp_aead.decrypt(PLAINTEXT, ASSOCIATED_DATA)

  def test_aead_encryption_works(self):
    kms_v1.KeyManagementServiceClient().encrypt.return_value = (
        kms_v1.types.EncryptResponse(ciphertext=CIPHERTEXT)
    )
    gcp_client = gcpkms.GcpKmsClient(KEY_URI1, CREDENTIAL_PATH)
    gcp_aead = gcp_client.get_aead(KEY_URI1)
    ciphertext = gcp_aead.encrypt(PLAINTEXT, ASSOCIATED_DATA)
    self.assertEqual(ciphertext, CIPHERTEXT)

  def test_aead_decryption_works(self):
    kms_v1.KeyManagementServiceClient().decrypt.return_value = (
        kms_v1.types.DecryptResponse(plaintext=PLAINTEXT)
    )
    gcp_client = gcpkms.GcpKmsClient(KEY_URI1, CREDENTIAL_PATH)
    gcp_aead = gcp_client.get_aead(KEY_URI1)
    plaintext = gcp_aead.decrypt(CIPHERTEXT, ASSOCIATED_DATA)
    self.assertEqual(plaintext, PLAINTEXT)


if __name__ == '__main__':
  absltest.main()
