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
"""Test for obtain_and_use_a_primitive."""
from absl.testing import absltest

from tink import aead

import load_cleartext_keyset
import obtain_and_use_a_primitive

_KMS_AEAD_KEY = r"""{
  "key": [
    {
      "keyData": {
        "keyMaterialType": "SYMMETRIC",
        "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
        "value": "GiBWyUfGgYk3RTRhj/LIUzSudIWlyjCftCOypTr0jCNSLg=="
      },
      "keyId": 294406504,
      "outputPrefixType": "TINK",
      "status": "ENABLED"
    }
  ],
  "primaryKeyId": 294406504
}"""


class ObtainAndUseAPrimitiveTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    aead.register()

  def test_obtain_and_use_a_primitive_encrypt_decrypt(self):
    keyset_handle = load_cleartext_keyset.LoadKeyset(_KMS_AEAD_KEY)

    # Encrypt/decrypt.
    plaintext = b'Some plaintext'
    associated_data = b'Some associated data'
    ciphertext = obtain_and_use_a_primitive.AeadEncrypt(keyset_handle,
                                                        plaintext,
                                                        associated_data)
    self.assertEqual(
        obtain_and_use_a_primitive.AeadDecrypt(keyset_handle, ciphertext,
                                               associated_data), plaintext)


if __name__ == '__main__':
  absltest.main()
