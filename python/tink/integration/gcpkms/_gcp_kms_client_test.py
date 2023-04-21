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

"""Tests for tink.python.tink.integration.gcp_kms_client."""

import os

from absl.testing import absltest

from tink.integration import gcpkms
from tink.testing import helper


CREDENTIAL_PATH = os.path.join(helper.tink_py_testdata_path(),
                               'gcp/credential.json')


class GcpKmsClientTest(absltest.TestCase):

  def test_client_bound_to_key_uri(self):
    gcp_key1 = 'gcp-kms://projects/someProject/.../cryptoKeys/key1'
    gcp_key2 = 'gcp-kms://projects/otherProject/.../cryptoKeys/key2'
    non_gcp_key = 'aws-kms://arn:aws:kms:us-west-2:acc:other/key3'

    gcp_client = gcpkms.GcpKmsClient(gcp_key1, CREDENTIAL_PATH)

    self.assertEqual(gcp_client.does_support(gcp_key1), True)
    self.assertEqual(gcp_client.does_support(gcp_key2), False)
    self.assertEqual(gcp_client.does_support(non_gcp_key), False)

  def test_client_not_bound_to_key_uri(self):
    gcp_key1 = 'gcp-kms://projects/someProject/.../cryptoKeys/key1'
    gcp_key2 = 'gcp-kms://projects/otherProject/.../cryptoKeys/key2'
    non_gcp_key = 'aws-kms://arn:aws:kms:us-west-2:acc:other/key3'

    gcp_client = gcpkms.GcpKmsClient(None, CREDENTIAL_PATH)

    self.assertEqual(gcp_client.does_support(gcp_key1), True)
    self.assertEqual(gcp_client.does_support(gcp_key2), True)
    self.assertEqual(gcp_client.does_support(non_gcp_key), False)

  def test_client_empty_key_uri(self):
    gcp_key = 'gcp-kms://projects/someProject/.../cryptoKeys/key1'
    gcp_client = gcpkms.GcpKmsClient('', CREDENTIAL_PATH)
    self.assertEqual(gcp_client.does_support(gcp_key), True)

  def test_client_invalid_path(self):
    with self.assertRaises(FileNotFoundError):
      gcpkms.GcpKmsClient(None, CREDENTIAL_PATH + 'corrupted')


if __name__ == '__main__':
  absltest.main()
