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
"""Tests for tink.python.tink.integration.hcvault_kms_client."""

from absl.testing import absltest

import tink
from tink.integration import hcvault
from tink.integration.hcvault import _hcvault_kms_client
from tink.testing import helper


TOKEN = "hvs.LPUqFLiJZXO3Q8kNtCawP33i" # Your auth token

#KEY_URI = ('hcvault://hcvault.corp.com:8200/transit/keys/key-1')
KEY_URI = ('hcvault://10.10.18.215:8200/transit/keys/key-1')

GCP_KEY_URI = ('gcp-kms://projects/tink-test-infrastructure/locations/global/'
               'keyRings/unit-and-integration-testing/cryptoKeys/aead-key')


class HcVaultKmsClientTest(absltest.TestCase):

  def test_client_bound_to_key_uri(self):
    hcvault_client = hcvault.HcVaultKmsClient(KEY_URI, TOKEN)

    self.assertEqual(hcvault_client.does_support(KEY_URI), True)
    self.assertEqual(hcvault_client.does_support(GCP_KEY_URI), False)

  def test_wrong_key_uri(self):
    with self.assertRaises(tink.TinkError):
      hcvault.HcVaultKmsClient(GCP_KEY_URI, TOKEN)

  def test_client_empty_key_uri(self):
    hcvault_client = hcvault.HcVaultKmsClient('', TOKEN)
    self.assertEqual(hcvault_client.does_support(KEY_URI), False)

  def test_client_invalid_token(self):
    with self.assertRaises(ValueError):
      hcvault.HcVaultKmsClient(KEY_URI, None)

  def test_parse_valid_credentials_works(self):
    hcvault.HcVaultKmsClient(KEY_URI, TOKEN)
    assert True

if __name__ == '__main__':
  absltest.main()
