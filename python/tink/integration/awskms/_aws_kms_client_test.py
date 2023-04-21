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
"""Tests for tink.python.tink.integration.aws_kms_client."""

import os

import tempfile

from absl.testing import absltest

import tink
from tink.integration import awskms
from tink.integration.awskms import _aws_kms_client
from tink.testing import helper


CREDENTIAL_PATH = os.path.join(helper.tink_py_testdata_path(),
                               'aws/credentials.ini')
KEY_URI = ('aws-kms://arn:aws:kms:us-east-2:235739564943:key/'
           '3ee50705-5a82-4f5b-9753-05c4f473922f')
KEY_URI_2 = ('aws-kms://arn:aws:kms:us-east-2:235739564943:key/'
             'b3ca2efd-a8fb-47f2-b541-7e20f8c5cd11')
GCP_KEY_URI = ('gcp-kms://projects/tink-test-infrastructure/locations/global/'
               'keyRings/unit-and-integration-testing/cryptoKeys/aead-key')


class AwsKmsClientTest(absltest.TestCase):

  def test_client_bound_to_key_uri(self):
    aws_client = awskms.AwsKmsClient(KEY_URI, CREDENTIAL_PATH)

    self.assertEqual(aws_client.does_support(KEY_URI), True)
    self.assertEqual(aws_client.does_support(KEY_URI_2), False)
    self.assertEqual(aws_client.does_support(GCP_KEY_URI), False)

  def test_client_not_bound_to_key_uri(self):
    aws_client = awskms.AwsKmsClient('', CREDENTIAL_PATH)

    self.assertEqual(aws_client.does_support(KEY_URI), True)
    self.assertEqual(aws_client.does_support(KEY_URI_2), True)
    self.assertEqual(aws_client.does_support(GCP_KEY_URI), False)

  def test_wrong_key_uri(self):
    with self.assertRaises(tink.TinkError):
      awskms.AwsKmsClient(GCP_KEY_URI, CREDENTIAL_PATH)

  def test_client_empty_key_uri(self):
    aws_client = awskms.AwsKmsClient('', CREDENTIAL_PATH)
    self.assertEqual(aws_client.does_support(KEY_URI), True)

  def test_client_invalid_path(self):
    with self.assertRaises(ValueError):
      awskms.AwsKmsClient('', CREDENTIAL_PATH + 'corrupted')

  def test_wrong_credentials_path(self):
    with self.assertRaises(ValueError):
      awskms.AwsKmsClient(KEY_URI, '../credentials.txt')

  def test_parse_valid_credentials_works(self):
    config_file = tempfile.NamedTemporaryFile(delete=False)
    with open(config_file.name, 'w') as f:
      f.write("""
[otherSection]
aws_access_key_id = other_key_id
aws_secret_access_key = other_key

[default]
aws_access_key_id = key_id_123
aws_secret_access_key = key_123""")

    aws_access_key_id, aws_secret_access_key = _aws_kms_client._parse_config(
        config_file.name
    )
    self.assertEqual(aws_access_key_id, 'key_id_123')
    self.assertEqual(aws_secret_access_key, 'key_123')

    os.unlink(config_file.name)

  def test_parse_credentials_without_key_id_fails(self):
    config_file = tempfile.NamedTemporaryFile(delete=False)
    with open(config_file.name, 'w') as f:
      f.write("""
[default]
aws_secret_access_key = key_123""")
    with self.assertRaises(ValueError):
      _aws_kms_client._parse_config(config_file.name)

    os.unlink(config_file.name)

  def test_parse_credentials_without_key_fails(self):
    config_file = tempfile.NamedTemporaryFile(delete=False)
    with open(config_file.name, 'w') as f:
      f.write("""
[default]
aws_secret_access_key = key_123""")
    with self.assertRaises(ValueError):
      _aws_kms_client._parse_config(config_file.name)

    os.unlink(config_file.name)

  def test_parse_credentials_without_default_section_fails(self):
    config_file = tempfile.NamedTemporaryFile(delete=False)
    with open(config_file.name, 'w') as f:
      f.write("""
[otherSection]
aws_access_key_id = other_key_id
aws_secret_access_key = other_key""")
    with self.assertRaises(ValueError):
      _aws_kms_client._parse_config(config_file.name)

    os.unlink(config_file.name)

if __name__ == '__main__':
  absltest.main()
