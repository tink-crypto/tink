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
"""Tests for tink.python.tink.integration.aws_kms_client."""
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
KEY_URI = 'aws-kms://arn:aws:kms:us-east-2:235739564943:key/3ee50705-5a82-4f5b-9753-05c4f473922f'
BAD_KEY_URI = 'gcp-kms://projects/tink-test-infrastructure/locations/global/keyRings/unit-and-integration-testing/cryptoKeys/aead-key'


class AwsKmsClientTest(absltest.TestCase):

  def test_client_generation(self):
    aws_client = awskms.AwsKmsClient(KEY_URI, CREDENTIAL_PATH)
    self.assertNotEqual(aws_client, None)

  def test_wrong_key_uri(self):
    with self.assertRaises(core.TinkError):
      awskms.AwsKmsClient(BAD_KEY_URI, CREDENTIAL_PATH)

  def test_client_registration(self):
    aws_client = awskms.AwsKmsClient('', CREDENTIAL_PATH)
    aws_client.register_client('', CREDENTIAL_PATH)

  def test_client_not_bound(self):
    gcp_key1 = 'gcp-kms://projects/someProject/.../cryptoKeys/key1'

    aws_client = awskms.AwsKmsClient(KEY_URI, CREDENTIAL_PATH)

    self.assertEqual(aws_client.does_support(KEY_URI), True)
    self.assertEqual(aws_client.does_support(gcp_key1), False)

  def test_wrong_credentials_path(self):
    with self.assertRaises(ValueError):
      awskms.AwsKmsClient(KEY_URI, '../credentials.txt')


if __name__ == '__main__':
  absltest.main()
