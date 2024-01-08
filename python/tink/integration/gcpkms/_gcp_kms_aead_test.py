# Copyright 2024 Google LLC
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

"""Tests for tink.python.tink.integration.gcp_kms_aead."""

from absl.testing import absltest
from google.api_core import exceptions as core_exceptions
from google.cloud import kms_v1

from tink import core
from tink.integration.gcpkms import _gcp_kms_client


GCP_KEY_NAME = 'projects/p1/locations/global/keyRings/kr1/cryptoKeys/ck1'
PLAINTEXT = b'plaintext'
CIPHERTEXT = b'ciphertext'
ASSOCIATED_DATA = b'associated_data'


class CustomException(core_exceptions.GoogleAPIError):
  pass


class GcpKmsAeadTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    absltest.mock.patch.object(kms_v1, 'KeyManagementServiceClient').start()

  def tearDown(self):
    absltest.mock.patch.stopall()
    super().tearDown()

  def test_encryption_fails(self):
    kms_v1.KeyManagementServiceClient().encrypt.side_effect = CustomException()
    gcp_aead = _gcp_kms_client._GcpKmsAead(
        kms_v1.KeyManagementServiceClient(), GCP_KEY_NAME
    )
    with self.assertRaises(core.TinkError):
      gcp_aead.encrypt(CIPHERTEXT, ASSOCIATED_DATA)

  def test_decryption_fails(self):
    kms_v1.KeyManagementServiceClient().decrypt.side_effect = CustomException()
    gcp_aead = _gcp_kms_client._GcpKmsAead(
        kms_v1.KeyManagementServiceClient(), GCP_KEY_NAME
    )
    with self.assertRaises(core.TinkError):
      gcp_aead.decrypt(PLAINTEXT, ASSOCIATED_DATA)

  def test_encryption_works(self):
    kms_v1.KeyManagementServiceClient().encrypt.return_value = (
        kms_v1.types.EncryptResponse(ciphertext=CIPHERTEXT)
    )
    gcp_aead = _gcp_kms_client._GcpKmsAead(
        kms_v1.KeyManagementServiceClient(), GCP_KEY_NAME
    )
    ciphertext = gcp_aead.encrypt(PLAINTEXT, ASSOCIATED_DATA)
    self.assertEqual(ciphertext, CIPHERTEXT)

  def test_decryption_works(self):
    kms_v1.KeyManagementServiceClient().decrypt.return_value = (
        kms_v1.types.DecryptResponse(plaintext=PLAINTEXT)
    )
    gcp_aead = _gcp_kms_client._GcpKmsAead(
        kms_v1.KeyManagementServiceClient(), GCP_KEY_NAME
    )
    plaintext = gcp_aead.decrypt(CIPHERTEXT, ASSOCIATED_DATA)
    self.assertEqual(plaintext, PLAINTEXT)

if __name__ == '__main__':
  absltest.main()
