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

"""Tests for _insecure_keyset_handle."""

from absl.testing import absltest

import tink
from tink import _insecure_keyset_handle
from tink import aead
from tink import core
from tink import secret_key_access
from tink import tink_config


def setUpModule():
  tink_config.register()


class InvalidKeyAccess(core.KeyAccess):
  pass


class InsecureKeysetHandleTest(absltest.TestCase):

  def test_from_to_proto_keyset(self):
    keyset_handle = tink.new_keyset_handle(aead.aead_key_templates.AES128_GCM)
    proto_keyset = _insecure_keyset_handle.to_proto_keyset(
        keyset_handle, secret_key_access.TOKEN
    )
    keyset_handle2 = _insecure_keyset_handle.from_proto_keyset(
        proto_keyset, secret_key_access.TOKEN
    )

    # check that keyset_handle and keyset_handle2 are the same.
    plaintext = b'plaintext'
    associated_data = b'associated_data'
    primitive1 = keyset_handle.primitive(aead.Aead)
    ciphertext = primitive1.encrypt(plaintext, associated_data)
    primitive2 = keyset_handle2.primitive(aead.Aead)
    self.assertEqual(primitive2.decrypt(ciphertext, associated_data), plaintext)

    # check that they fail without secret_key_access.TOKEN
    with self.assertRaises(core.TinkError):
      _insecure_keyset_handle.to_proto_keyset(keyset_handle, InvalidKeyAccess())
    with self.assertRaises(core.TinkError):
      _insecure_keyset_handle.from_proto_keyset(
          proto_keyset, InvalidKeyAccess()
      )


if __name__ == '__main__':
  absltest.main()
