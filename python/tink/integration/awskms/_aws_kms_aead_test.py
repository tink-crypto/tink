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
"""Tests for tink.python.tink.integration.aws_kms_aead."""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import os

from absl.testing import absltest

from tink import core
from tink.integration import awskms
from tink.testing import helper

CREDENTIAL_PATH = os.path.join(helper.tink_root_path(),
                               'testdata/aws_credentials_cc.txt')
BAD_CREDENTIALS_PATH = os.path.join(helper.tink_root_path(),
                                    'testdata/bad_aws_credentials_cc.txt')
KEY_URI = 'aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f'
BAD_KEY_URI = 'gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/aead-key'


class AwsKmsAeadTest(absltest.TestCase):

  def test_encrypt_decrypt(self):
    aws_client = awskms.AwsKmsClient(KEY_URI, CREDENTIAL_PATH)
    aead = aws_client.get_aead(KEY_URI)

    plaintext = b'hello'
    associated_data = b'world'
    ciphertext = aead.encrypt(plaintext, associated_data)
    self.assertEqual(plaintext, aead.decrypt(ciphertext, associated_data))

    plaintext = b'hello'
    ciphertext = aead.encrypt(plaintext, b'')
    self.assertEqual(plaintext, aead.decrypt(ciphertext, b''))

  def test_corrupted_ciphertext(self):
    aws_client = awskms.AwsKmsClient(KEY_URI, CREDENTIAL_PATH)
    aead = aws_client.get_aead(KEY_URI)

    plaintext = b'helloworld'
    ciphertext = aead.encrypt(plaintext, b'')
    self.assertEqual(plaintext, aead.decrypt(ciphertext, b''))

    # Corrupt each byte once and check that decryption fails
    # NOTE: Skipping two bytes as they are malleable
    for byte_idx in [b for b in range(len(ciphertext)) if b not in [77, 123]]:
      tmp_ciphertext = list(ciphertext)
      tmp_ciphertext[byte_idx] ^= 1
      corrupted_ciphertext = bytes(tmp_ciphertext)
      with self.assertRaises(core.TinkError):
        aead.decrypt(corrupted_ciphertext, b'')

  def test_encrypt_with_bad_uri(self):
    with self.assertRaises(core.TinkError):
      aws_client = awskms.AwsKmsClient(KEY_URI, CREDENTIAL_PATH)
      aws_client.get_aead(BAD_KEY_URI)

  def test_encrypt_with_bad_credentials(self):
    aws_client = awskms.AwsKmsClient(KEY_URI, BAD_CREDENTIALS_PATH)
    aead = aws_client.get_aead(KEY_URI)

    plaintext = b'hello'
    associated_data = b'world'
    with self.assertRaises(core.TinkError):
      aead.encrypt(plaintext, associated_data)


if __name__ == '__main__':
  absltest.main()
