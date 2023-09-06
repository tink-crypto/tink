# Copyright 2023 Google LLC
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

"""Tests for kms_clients."""

from absl.testing import absltest
import tink
from tink import _kms_clients
from tink import aead
from tink import tink_config


def setUpModule():
  tink_config.register()


class FakeClient(_kms_clients.KmsClient):

  def __init__(self, key_uri):
    self.key_uri = key_uri

  def does_support(self, key_uri: str) -> bool:
    return key_uri == self.key_uri

  def get_aead(self, key_uri: str) -> aead.Aead:
    raise ValueError('unknown key_uri')


class KmsClientsTest(absltest.TestCase):

  def test_register_get_and_reset_kms_clients(self):
    client1 = FakeClient('key_uri1')
    client2 = FakeClient('key_uri2')
    client3 = FakeClient('key_uri3')
    tink.register_kms_client(client1)
    tink.register_kms_client(client2)
    tink.register_kms_client(client3)

    # returns the first registered client that supports the uri.
    self.assertEqual(tink.kms_client_from_uri('key_uri1'), client1)
    self.assertEqual(tink.kms_client_from_uri('key_uri2'), client2)
    with self.assertRaises(tink.TinkError):
      tink.kms_client_from_uri('unknown')

    _kms_clients.reset_kms_clients()
    with self.assertRaises(tink.TinkError):
      tink.kms_client_from_uri('key_uri1')


if __name__ == '__main__':
  absltest.main()
