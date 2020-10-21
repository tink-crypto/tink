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

"""Tests for tink.python.tink.integration.gcp_kms_aead."""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import os

from absl.testing import absltest

from tink import core
from tink.integration import gcpkms
from tink.testing import helper

CREDENTIAL_PATH = os.path.join(helper.tink_root_path(),
                               'testdata/credential.json')
KEY_URI = 'gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/aead-key'
LOCAL_KEY_URI = 'gcp-kms://projects/tink-test-infrastructure/locations/europe-west1/keyRings/unit-and-integration-test/cryptoKeys/aead-key'
BAD_KEY_URI = 'aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f'

if 'TEST_SRCDIR' in os.environ:
  # Set root certificates for gRPC in Bazel Test which are needed on MacOS
  os.environ['GRPC_DEFAULT_SSL_ROOTS_FILE_PATH'] = os.path.join(
      os.environ['TEST_SRCDIR'], 'google_root_pem/file/downloaded')


class GcpKmsAeadTest(absltest.TestCase):

  def test_encrypt_decrypt(self):
    gcp_client = gcpkms.GcpKmsClient(KEY_URI, CREDENTIAL_PATH)
    aead = gcp_client.get_aead(KEY_URI)

    plaintext = b'helloworld'
    ciphertext = aead.encrypt(plaintext, b'')
    self.assertEqual(plaintext, aead.decrypt(ciphertext, b''))

    plaintext = b'hello'
    associated_data = b'world'
    ciphertext = aead.encrypt(plaintext, associated_data)
    self.assertEqual(plaintext, aead.decrypt(ciphertext, associated_data))

  def test_encrypt_decrypt_localized_uri(self):
    gcp_client = gcpkms.GcpKmsClient(LOCAL_KEY_URI, CREDENTIAL_PATH)
    aead = gcp_client.get_aead(LOCAL_KEY_URI)

    plaintext = b'helloworld'
    ciphertext = aead.encrypt(plaintext, b'')
    self.assertEqual(plaintext, aead.decrypt(ciphertext, b''))

    plaintext = b'hello'
    associated_data = b'world'
    ciphertext = aead.encrypt(plaintext, associated_data)
    self.assertEqual(plaintext, aead.decrypt(ciphertext, associated_data))

  def test_encrypt_with_bad_uri(self):
    with self.assertRaises(core.TinkError):
      gcp_client = gcpkms.GcpKmsClient(KEY_URI, CREDENTIAL_PATH)
      gcp_client.get_aead(BAD_KEY_URI)

  def test_corrupted_ciphertext(self):
    gcp_client = gcpkms.GcpKmsClient(KEY_URI, CREDENTIAL_PATH)
    aead = gcp_client.get_aead(KEY_URI)

    plaintext = b'helloworld'
    ciphertext = aead.encrypt(plaintext, b'')
    self.assertEqual(plaintext, aead.decrypt(ciphertext, b''))

    # Corrupt each byte once and check that decryption fails
    # NOTE: Only starting at 4th byte here, as the 3rd byte is malleable
    #      (see b/146633745).
    for byte_idx in range(3, len(ciphertext)):
      tmp_ciphertext = list(ciphertext)
      tmp_ciphertext[byte_idx] ^= 1
      corrupted_ciphertext = bytes(tmp_ciphertext)
      with self.assertRaises(core.TinkError):
        aead.decrypt(corrupted_ciphertext, b'')

if __name__ == '__main__':
  # TODO(b/154273145): re-enable this.
  pass
  # absltest.main()
