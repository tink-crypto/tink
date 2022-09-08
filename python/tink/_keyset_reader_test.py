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

"""Tests for tink.python.tink._keyset_reader."""

from typing import cast
from absl.testing import absltest

from tink.proto import tink_pb2
import tink
from tink import core


class JsonKeysetReaderTest(absltest.TestCase):

  def test_read(self):
    json_keyset = """
        {
          "primaryKeyId": 42,
          "key": [
            {
              "keyData": {
                "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
                "keyMaterialType": "SYMMETRIC",
                "value": "GhCS/1+ejWpx68NfGt6ziYHd"
              },
              "outputPrefixType": "TINK",
              "keyId": 42,
              "status": "ENABLED"
            }
          ]
        }"""
    reader = tink.JsonKeysetReader(json_keyset)
    keyset = reader.read()
    self.assertEqual(keyset.primary_key_id, 42)
    self.assertLen(keyset.key, 1)

  def test_read_invalid(self):
    reader = tink.JsonKeysetReader('not json')
    with self.assertRaises(core.TinkError):
      reader.read()

  def test_read_rejects_negative_key_id(self):
    json_keyset = """
        {
          "primaryKeyId": -42,
          "key": [
            {
              "keyData": {
                "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
                "keyMaterialType": "SYMMETRIC",
                "value": "GhCS/1+ejWpx68NfGt6ziYHd"
              },
              "outputPrefixType": "TINK",
              "keyId": -42,
              "status": "ENABLED"
            }
          ]
        }"""
    reader = tink.JsonKeysetReader(json_keyset)
    with self.assertRaises(core.TinkError):
      reader.read()

  def test_read_rejects_key_id_larger_than_uint32(self):
    # 4294967296 = 2^32, which is too large for uint32.
    json_keyset = """
        {
          "primaryKeyId": 4294967296,
          "key": [
            {
              "keyData": {
                "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
                "keyMaterialType": "SYMMETRIC",
                "value": "GhCS/1+ejWpx68NfGt6ziYHd"
              },
              "outputPrefixType": "TINK",
              "keyId": 4294967296,
              "status": "ENABLED"
            }
          ]
        }"""
    reader = tink.JsonKeysetReader(json_keyset)
    with self.assertRaises(core.TinkError):
      reader.read()

  def test_read_encrypted(self):
    # encryptedKeyset is a base64-encoding of 'some ciphertext with keyset'
    json_encrypted_keyset = """
        {
          "encryptedKeyset": "c29tZSBjaXBoZXJ0ZXh0IHdpdGgga2V5c2V0",
          "keysetInfo": {
            "primaryKeyId": 42,
            "keyInfo": [
              {
                "typeUrl": "type.googleapis.com/google.crypto.tink.AesGcmKey",
                "outputPrefixType": "TINK",
                "keyId": 42,
                "status": "ENABLED"
              }
            ]
          }
        }"""
    reader = tink.JsonKeysetReader(json_encrypted_keyset)
    enc_keyset = reader.read_encrypted()
    self.assertEqual(enc_keyset.encrypted_keyset,
                     b'some ciphertext with keyset')
    self.assertLen(enc_keyset.keyset_info.key_info, 1)
    self.assertEqual(enc_keyset.keyset_info.key_info[0].type_url,
                     'type.googleapis.com/google.crypto.tink.AesGcmKey')

  def test_read_encrypted_invalid(self):
    reader = tink.JsonKeysetReader('not json')
    with self.assertRaises(core.TinkError):
      reader.read_encrypted()


class BinaryKeysetReaderTest(absltest.TestCase):

  def test_read(self):
    keyset = tink_pb2.Keyset()
    keyset.primary_key_id = 42
    key = keyset.key.add()
    key.key_data.type_url = 'type.googleapis.com/google.crypto.tink.AesGcmKey'
    key.key_data.key_material_type = tink_pb2.KeyData.SYMMETRIC
    key.key_data.value = b'GhCS/1+ejWpx68NfGt6ziYHd'
    key.output_prefix_type = tink_pb2.TINK
    key.key_id = 42
    key.status = tink_pb2.ENABLED
    reader = tink.BinaryKeysetReader(keyset.SerializeToString())
    self.assertEqual(keyset, reader.read())

  def test_read_none(self):
    with self.assertRaises(core.TinkError):
      reader = tink.BinaryKeysetReader(cast(bytes, None))
      reader.read()

  def test_read_empty(self):
    with self.assertRaises(core.TinkError):
      reader = tink.BinaryKeysetReader(b'')
      reader.read()

  def test_read_invalid(self):
    with self.assertRaises(core.TinkError):
      reader = tink.BinaryKeysetReader(b'some weird data')
      reader.read()

  def test_read_encrypted(self):
    encrypted_keyset = tink_pb2.EncryptedKeyset()
    encrypted_keyset.encrypted_keyset = b'c29tZSBjaXBoZXJ0ZXh0IHdpdGgga2V5c2V0'
    encrypted_keyset.keyset_info.primary_key_id = 42
    key_info = encrypted_keyset.keyset_info.key_info.add()
    key_info.type_url = 'type.googleapis.com/google.crypto.tink.AesGcmKey'
    key_info.output_prefix_type = tink_pb2.TINK
    key_info.key_id = 42
    key_info.status = tink_pb2.ENABLED
    reader = tink.BinaryKeysetReader(
        encrypted_keyset.SerializeToString())
    self.assertEqual(encrypted_keyset, reader.read_encrypted())

  def test_read_encrypted_none(self):
    with self.assertRaises(core.TinkError):
      reader = tink.BinaryKeysetReader(cast(bytes, None))
      reader.read_encrypted()

  def test_read_encrypted_empty(self):
    with self.assertRaises(core.TinkError):
      reader = tink.BinaryKeysetReader(b'')
      reader.read_encrypted()

  def test_read_encrypted_invalid(self):
    with self.assertRaises(core.TinkError):
      reader = tink.BinaryKeysetReader(b'some weird data')
      reader.read_encrypted()


if __name__ == '__main__':
  absltest.main()
