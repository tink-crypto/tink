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
from absl.testing import parameterized
from google.api_core import exceptions as core_exceptions
from google.cloud import kms_v1

from tink import core
from tink.integration.gcpkms import _gcp_kms_client


GCP_KEY_NAME = 'projects/p1/locations/global/keyRings/kr1/cryptoKeys/ck1'
PLAINTEXT = b'plaintext'
CIPHERTEXT = b'ciphertext'
ASSOCIATED_DATA = b'associated_data'
STRING_63 = 'A' * 63
STRING_64 = 'A' * 64
FAKE_PROJECT_ID = '~@#$%^&*()_+|}{POI}?><213:"L{O}µ÷åß∑' * 5


class CustomException(core_exceptions.GoogleAPIError):
  pass


class GcpKmsAeadTest(parameterized.TestCase):

  def setUp(self):
    super().setUp()
    absltest.mock.patch.object(kms_v1, 'KeyManagementServiceClient').start()

  def tearDown(self):
    absltest.mock.patch.stopall()
    super().tearDown()

  def test_client_null(self):
    with self.assertRaises(core.TinkError):
      _gcp_kms_client._GcpKmsAead(None, GCP_KEY_NAME)

  @parameterized.parameters(
      '',
      None,
      'wrong/kms/key/format',
      'projects/p1/locations/global/keyRings/kr1/cryptoKeys',
      'projects/p1/locations/global/keyRings/kr1/cryptoKeys/ck1/',
      'projects/p1/locations/global@/keyRings/kr1/cryptoKeys/ck1',
      'projects/p1/locations/global/keyRings/kr1@/cryptoKeys/ck1',
      'projects/p1/locations/global/keyRings/kr1/cryptoKeys/ck1@',
      'projects/p1/locations/' + STRING_64 + '/keyRings/kr1/cryptoKeys/ck1',
      'projects/p1/locations/global/keyRings/' + STRING_64 + '/cryptoKeys/ck1',
      'projects/p1/locations/global/keyRings/kr1/cryptoKeys/' + STRING_64,
      'projects/p1/locations/global/keyRings/kr1/cryptoKeys/ck1/cryptoKeyVersions/1',
      'gcprojects://projects/p1/locations/global/keyRings/kr1/cryptoKeys/ck1',
  )
  def test_key_name_format_wrong(self, key_name):
    with self.assertRaises(core.TinkError):
      _gcp_kms_client._GcpKmsAead(kms_v1.KeyManagementServiceClient(), key_name)

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

  @parameterized.parameters(
      GCP_KEY_NAME,
      'projects/p1@comp!/locations/global/keyRings/kr1/cryptoKeys/ck1',
      'projects/' + FAKE_PROJECT_ID + '/locations/l1/keyRings/k1/cryptoKeys/c1',
      'projects/p1/locations/' + STRING_63 + '/keyRings/kr1/cryptoKeys/ck1',
      'projects/p1/locations/global/keyRings/' + STRING_63 + '/cryptoKeys/ck1',
      'projects/p1/locations/global/keyRings/kr1/cryptoKeys/' + STRING_63,
  )
  def test_encryption_works(self, key_name):
    kms_v1.KeyManagementServiceClient().encrypt.return_value = (
        kms_v1.types.EncryptResponse(name=GCP_KEY_NAME, ciphertext=CIPHERTEXT)
    )
    gcp_aead = _gcp_kms_client._GcpKmsAead(
        kms_v1.KeyManagementServiceClient(), key_name
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
