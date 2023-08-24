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
"""Tests for tink.python.tink.integration.vaultkms_aead."""

import hvac

from absl.testing import absltest

import tink
from tink import aead
from tink.aead import _kms_aead_key_manager
from tink.integration import hcvault
from tink.integration.hcvault import _hcvault_kms_client
from tink.testing import helper


TOKEN = "hvs.LPUqFLiJZXO3Q8kNtCawP33i" # Your auth token

BAD_TOKEN = "notavalidtoken"

#KEY_URI = ('hcvault://hcvault.corp.com:8200/transit/keys/key-1') # Replace this with your vault URI
KEY_URI = ('http://10.10.18.215:8200/transit/keys/key-1') # Replace this with your vault URI

GCP_KEY_URI = ('gcp-kms://projects/tink-test-infrastructure/locations/global/'
               'keyRings/unit-and-integration-testing/cryptoKeys/aead-key')

CLIENT = None
BAD_CLIENT = None


def setUpModule():
  aead.register()
  global CLIENT
  global BAD_CLIENT
  CLIENT = hvac.Client(url=KEY_URI, token=TOKEN, verify=False)
  BAD_CLIENT = hvac.Client(url=KEY_URI, token=BAD_TOKEN, verify=False)

class HcVaultAeadTest(absltest.TestCase):

  def tearDown(self):
    super().tearDown()
    #_kms_aead_key_manager.reset_kms_clients()

  def test_encrypt_decrypt(self):
    vaultaead = hcvault.create_aead(KEY_URI, CLIENT)

    plaintext = b'hello'
    associated_data = b'world'
    ciphertext = vaultaead.encrypt(plaintext, associated_data)
    self.assertEqual(plaintext, vaultaead.decrypt(ciphertext, associated_data))

    plaintext = b'hello'
    ciphertext = vaultaead.encrypt(plaintext, b'')
    self.assertEqual(plaintext, vaultaead.decrypt(ciphertext, b''))

  def test_corrupted_ciphertext(self):
    vaultaead = hcvault.create_aead(KEY_URI, CLIENT)

    plaintext = b'helloworld'
    ciphertext = vaultaead.encrypt(plaintext, b'')
    self.assertEqual(plaintext, vaultaead.decrypt(ciphertext, b''))

    # Corrupt each byte once and check that decryption fails
    for byte_idx in [b for b in range(len(ciphertext))]:
      tmp_ciphertext = list(ciphertext)
      tmp_ciphertext[byte_idx] ^= 2
      corrupted_ciphertext = bytes(tmp_ciphertext)
      with self.assertRaises(tink.TinkError):
        vaultaead.decrypt(corrupted_ciphertext, b'')

  def test_encrypt_with_bad_uri(self):
    with self.assertRaises(tink.TinkError):
      hcvault.create_aead(GCP_KEY_URI, CLIENT)

  def test_encrypt_with_bad_client(self):
    with self.assertRaises(tink.TinkError):
      vaultaead = hcvault.create_aead(KEY_URI, BAD_CLIENT)

      plaintext = b'hello'
      associated_data = b'world'
      vaultaead.encrypt(plaintext, associated_data)

if __name__ == '__main__':
  absltest.main()
