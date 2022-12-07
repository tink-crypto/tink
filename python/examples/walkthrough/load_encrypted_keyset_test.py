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
"""Test for load_encrypted_keyset."""
import base64
import io

from absl.testing import absltest

import tink

from tink import aead
from tink import cleartext_keyset_handle

import load_encrypted_keyset
from tink.testing import fake_kms

_FAKE_KMS_AEAD_KEYSET = r"""{
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

_KEYSET_TO_ENCRYPT = r"""{
  "key": [
    {
      "keyData": {
        "keyMaterialType": "SYMMETRIC",
        "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
        "value": "GhD+9l0RANZjzZEZ8PDp7LRW"
      },
      "keyId": 1931667682,
      "outputPrefixType": "TINK",
      "status": "ENABLED"
    }
  ],
  "primaryKeyId": 1931667682
}"""

# Encryption of _KEYSET_TO_ENCRYPT with _FAKE_KMS_AEAD_KEYSET with no
# associated data.
_ENCRYPTED_KEYSET = r"""{
  "encryptedKeyset": "ARGMSWi6YHyZ/Oqxl00XSq631a0q2UPmf+rCvCIAggSZrwCmxFF797MpY0dqgaXu1fz2eQ8zFNhlyTXv9kwg1kY6COpyhY/68zNBUkyKX4CharLYfpg1LgRl+6rMzIQa0XDHh7ZDmp1CevzecZIKnG83uDRHxxSv3h8c/Kc="
}"""


def _get_base64_encoded_keyset_from_serialized_json(
    serialized_json_keyset: str) -> str:
  """Returns a Base64 encoded keyset from a JSON serialized keyset as str."""
  keyset_handle = cleartext_keyset_handle.read(
      tink.JsonKeysetReader(serialized_json_keyset))
  stream = io.BytesIO()
  writer = tink.BinaryKeysetWriter(stream)
  cleartext_keyset_handle.write(writer, keyset_handle)
  return base64.urlsafe_b64encode(stream.getvalue()).decode('utf-8')


# Fake KMS keys are base64-encoded keysets.
_FAKE_KMS_KEY_URI = (
    'fake-kms://' +
    _get_base64_encoded_keyset_from_serialized_json(_FAKE_KMS_AEAD_KEYSET))


class LoadEncryptedKeysetTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    aead.register()
    fake_kms.register_client()

  def test_load_encrypted_keyset_fails_if_kms_key_is_invalid(self):
    with self.assertRaises(tink.TinkError):
      load_encrypted_keyset.LoadEncryptedKeyset(
          _ENCRYPTED_KEYSET,
          kms_key_uri='fake-kms://invalid-kms-key',
          associated_data=b'')

  def test_load_encrypted_keyset_fails_if_keyset_is_invalid(self):
    with self.assertRaises(tink.TinkError):
      load_encrypted_keyset.LoadEncryptedKeyset(
          'Invalid keyset', _FAKE_KMS_KEY_URI, associated_data=b'')

  def test_load_encrypted_keyset_returns_a_valid_keyset(self):
    keyset_handle = load_encrypted_keyset.LoadEncryptedKeyset(
        _ENCRYPTED_KEYSET, _FAKE_KMS_KEY_URI, associated_data=b'')

    # Make sure that we can use this primitive.
    aead_primitive = keyset_handle.primitive(aead.Aead)
    plaintext = b'Some plaintext'
    associated_data = b'Some associated data'
    ciphertext = aead_primitive.encrypt(plaintext, associated_data)
    self.assertEqual(
        aead_primitive.decrypt(ciphertext, associated_data), plaintext)

    # Make sure we can use the loaded keyset to decrypt a ciphertext encrypted
    # with _KEYSET_TO_ENCRYPT.
    expected_keyset_handle = cleartext_keyset_handle.read(
        tink.JsonKeysetReader(_KEYSET_TO_ENCRYPT))
    expected_aead = expected_keyset_handle.primitive(aead.Aead)
    self.assertEqual(
        aead_primitive.decrypt(
            expected_aead.encrypt(plaintext, associated_data), associated_data),
        plaintext)
    # Make sure we can use _KEYSET_TO_ENCRYPT to decrypt the ciphertext produced
    # by the keyset we loaded.
    self.assertEqual(
        expected_aead.decrypt(
            aead_primitive.encrypt(plaintext, associated_data),
            associated_data), plaintext)


if __name__ == '__main__':
  absltest.main()
