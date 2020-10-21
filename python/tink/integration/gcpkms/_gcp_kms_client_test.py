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

"""Tests for tink.python.tink.integration.gcp_kms_client."""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import os

from absl.testing import absltest

from tink.integration import gcpkms
from tink.testing import helper


CREDENTIAL_PATH = os.path.join(helper.tink_root_path(),
                               'testdata/credential.json')


class GcpKmsClientTest(absltest.TestCase):

  def test_client_generation(self):
    gcp_client = gcpkms.GcpKmsClient('', CREDENTIAL_PATH)
    self.assertNotEqual(gcp_client, None)

  def test_client_registration(self):
    gcp_client = gcpkms.GcpKmsClient('', CREDENTIAL_PATH)
    gcp_client.register_client('', CREDENTIAL_PATH)

  def test_client_invalid_path(self):
    with self.assertRaises(ValueError):
      gcpkms.GcpKmsClient('', CREDENTIAL_PATH + 'corrupted')

  def test_client_not_bound(self):
    gcp_key1 = 'gcp-kms://projects/someProject/.../cryptoKeys/key1'
    gcp_key2 = 'gcp-kms://projects/otherProject/.../cryptoKeys/key2'
    non_gcp_key = 'aws-kms://arn:aws:kms:us-west-2:acc:other/key3'

    gcp_client = gcpkms.GcpKmsClient('', CREDENTIAL_PATH)

    self.assertEqual(gcp_client.does_support(gcp_key1), True)
    self.assertEqual(gcp_client.does_support(gcp_key2), True)
    self.assertEqual(gcp_client.does_support(non_gcp_key), False)

if __name__ == '__main__':
  absltest.main()
