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

import os

from absl.testing import absltest
import botocore

import tink
from tink import aead
from tink.aead import _kms_aead_key_manager
from tink.integration import hcvault
from tink.integration.hcvault import _hcvault_kms_client
from tink.testing import helper


TOKEN = "" # Your auth token

BAD_TOKEN = "notavalidtoken"

KEY_URI = ('hcvault://hcvault.corp.com:8200/transit/keys/key-1')

GCP_KEY_URI = ('gcp-kms://projects/tink-test-infrastructure/locations/global/'
               'keyRings/unit-and-integration-testing/cryptoKeys/aead-key')


def setUpModule():
  aead.register()


class HcVaultAeadTest(absltest.TestCase):

  def tearDown(self):
    super().tearDown()
    _kms_aead_key_manager.reset_kms_clients()

  def test_encrypt_decrypt(self):
    vaultclient = hcvault.HcVaultClient(KEY_URI, TOKEN)
    vaultaead = vaultclient.get_aead(KEY_URI)

    plaintext = b'hello'
    associated_data = b'world'
    ciphertext = vaultaead.encrypt(plaintext, associated_data)
    self.assertEqual(plaintext, vaultaead.decrypt(ciphertext, associated_data))

    plaintext = b'hello'
    ciphertext = vaultaead.encrypt(plaintext, b'')
    self.assertEqual(plaintext, vaultaead.decrypt(ciphertext, b''))

  def test_corrupted_ciphertext(self):
    vaultclient = hcvault.HcVaultClient(KEY_URI, TOKEN)
    vaultaead = vaultclient.get_aead(KEY_URI)

    plaintext = b'helloworld'
    ciphertext = vaultaead.encrypt(plaintext, b'')
    self.assertEqual(plaintext, vaultaead.decrypt(ciphertext, b''))

    # Corrupt each byte once and check that decryption fails
    # NOTE: Skipping two bytes as they are malleable
    for byte_idx in [b for b in range(len(ciphertext)) if b not in [77, 123]]:
      tmp_ciphertext = list(ciphertext)
      tmp_ciphertext[byte_idx] ^= 1
      corrupted_ciphertext = bytes(tmp_ciphertext)
      with self.assertRaises(tink.TinkError):
        vaultaead.decrypt(corrupted_ciphertext, b'')

  def test_encrypt_with_bad_uri(self):
    with self.assertRaises(tink.TinkError):
      vaultclient = hcvault.HcVaultClient(KEY_URI, TOKEN)
      vaultclient.get_aead(GCP_KEY_URI)

  def test_encrypt_with_bad_token(self):
    vaultclient = hcvault.HcVaultClient(KEY_URI, BAD_TOKEN)
    vaultaead = vaultclient.get_aead(KEY_URI)

    plaintext = b'hello'
    associated_data = b'world'
    with self.assertRaises(tink.TinkError):
      vaultaead.encrypt(plaintext, associated_data)

  def test_client_registration(self):
    # Register AWS KMS Client bound to KEY_URI.
    hcvault.HcVaultClient.register_client(KEY_URI, TOKEN)

    # Create a keyset handle for KEY_URI and use it.
    handle = tink.new_keyset_handle(
        aead.aead_key_templates.create_kms_aead_key_template(KEY_URI)
    )
    vaultaead = handle.primitive(aead.Aead)
    ciphertext = vaultaead.encrypt(b'plaintext', b'associated_data')
    self.assertEqual(
        b'plaintext', vaultaead.decrypt(ciphertext, b'associated_data')
    )

  def test_encrypt_with_default_credentials(self):
    # If no credentials_path is provided, this path here is used by default.
    os.environ['AWS_SHARED_CREDENTIALS_FILE'] = TOKEN

    vaultclient = hcvault.HcVaultClient(key_uri=KEY_URI, credentials_path=None)
    vaultaead = vaultclient.get_aead(KEY_URI)

    ciphertext = vaultaead.encrypt(b'plaintext', b'associated_data')
    self.assertEqual(
        b'plaintext', vaultaead.decrypt(ciphertext, b'associated_data')
    )

if __name__ == '__main__':
  absltest.main()
