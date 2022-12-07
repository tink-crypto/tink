# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Test for load_cleartext_keyset."""
from absl.testing import absltest

import tink

from tink import aead

import load_cleartext_keyset

_AES_GCM_KEYSET = r"""{
      "key": [{
          "keyData": {
              "keyMaterialType":
                  "SYMMETRIC",
              "typeUrl":
                  "type.googleapis.com/google.crypto.tink.AesGcmKey",
              "value":
                  "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
          },
          "keyId": 294406504,
          "outputPrefixType": "TINK",
          "status": "ENABLED"
      }],
      "primaryKeyId": 294406504
  }"""


class LoadCleartextKeysetTest(absltest.TestCase):

  def test_load_cleartext_keyset_fails_if_keyset_is_invalid(self):
    with self.assertRaises(tink.TinkError):
      load_cleartext_keyset.LoadKeyset('Invlid keyset')

  def test_load_cleartext_keyset_produces_a_valid_keyset(self):
    aead.register()
    keyset_handle = load_cleartext_keyset.LoadKeyset(_AES_GCM_KEYSET)
    # Make sure that we can use this primitive.
    aead_primitive = keyset_handle.primitive(aead.Aead)
    plaintext = b'Some plaintext'
    associated_data = b'Some associated data'
    ciphertext = aead_primitive.encrypt(plaintext, associated_data)
    self.assertEqual(
        aead_primitive.decrypt(ciphertext, associated_data), plaintext)


if __name__ == '__main__':
  absltest.main()
