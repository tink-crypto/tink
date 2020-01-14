# Copyright 2019 Google LLC.
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

"""Tests for tink.python.integration.gcp_kms_aead."""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import os

from absl.testing import absltest

from tink.python.integration.gcpkms.gcp_kms_client import GcpKmsClient

CREDENTIAL_PATH = os.environ['TEST_SRCDIR'] + '/tink/testdata/credential.json'
KEY_URI = 'gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/aead-key'


class GcpKmsAeadTest(absltest.TestCase):

  def test_encrypt_decrypt(self):
    gcp_client = GcpKmsClient(KEY_URI, CREDENTIAL_PATH)
    aead = gcp_client.get_aead(KEY_URI)

    plaintext = b'helloworld'
    ciphertext = aead.encrypt(plaintext, None)
    self.assertEqual(plaintext, aead.decrypt(ciphertext, None))

    plaintext = b'hello'
    associated_data = b'world'
    ciphertext = aead.encrypt(plaintext, associated_data)
    self.assertEqual(plaintext, aead.decrypt(ciphertext, associated_data))

  def test_corrupted_ciphertext(self):
    gcp_client = GcpKmsClient(KEY_URI, CREDENTIAL_PATH)
    aead = gcp_client.get_aead(KEY_URI)

    plaintext = b'helloworld'
    ciphertext = aead.encrypt(plaintext, None)
    self.assertEqual(plaintext, aead.decrypt(ciphertext, None))

    # Corrupt each byte once and check that decryption fails
    # NOTE: Only starting at 4th byte here, as the 3rd byte is malleable
    #      (see b/146633745).
    for byte_idx in range(3, len(ciphertext)):
      tmp_ciphertext = list(ciphertext)
      tmp_ciphertext[byte_idx] ^= 1
      corrupted_ciphertext = bytes(tmp_ciphertext)
      with self.assertRaises(ValueError):
        aead.decrypt(corrupted_ciphertext, None)

if __name__ == '__main__':
  absltest.main()
