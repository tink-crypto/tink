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

"""Tests for tink.python.tink.json_json_proto_keyset_format."""

import io

from absl.testing import absltest

import tink
from tink import aead
from tink import core
from tink import hybrid
from tink import secret_key_access
from tink import tink_config


def setUpModule():
  tink_config.register()


class InvalidKeyAccess(core.KeyAccess):
  pass


class TinkJsonProtoKeysetFormatTest(absltest.TestCase):

  def test_serialize_parse(self):
    keyset_handle = tink.new_keyset_handle(aead.aead_key_templates.AES128_GCM)
    serialized_keyset = tink.json_proto_keyset_format.serialize(
        keyset_handle, secret_key_access.TOKEN
    )
    parsed_keyset_handle = tink.json_proto_keyset_format.parse(
        serialized_keyset, secret_key_access.TOKEN
    )

    # check that keyset_handle and parsed_handle are the same.
    plaintext = b'plaintext'
    associated_data = b'associated_data'
    primitive1 = keyset_handle.primitive(aead.Aead)
    ciphertext = primitive1.encrypt(plaintext, associated_data)
    primitive2 = parsed_keyset_handle.primitive(aead.Aead)
    self.assertEqual(primitive2.decrypt(ciphertext, associated_data), plaintext)

    # check that serialize and parse fail without secret_key_access.TOKEN
    with self.assertRaises(core.TinkError):
      tink.json_proto_keyset_format.serialize(keyset_handle, InvalidKeyAccess())
    with self.assertRaises(core.TinkError):
      tink.json_proto_keyset_format.parse(serialized_keyset, InvalidKeyAccess())

  def test_serialize_parse_without_secret(self):
    private_handle = tink.new_keyset_handle(
        hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM
    )
    public_handle = private_handle.public_keyset_handle()

    # serialize and parse public_handle
    serialized = tink.json_proto_keyset_format.serialize_without_secret(
        public_handle
    )
    parsed = tink.json_proto_keyset_format.parse_without_secret(serialized)

    # check that parsed works with private_handle
    plaintext = b'plaintext'
    context_info = b'context info'
    hybrid_enc = parsed.primitive(hybrid.HybridEncrypt)
    ciphertext = hybrid_enc.encrypt(plaintext, context_info)
    hybrid_dec = private_handle.primitive(hybrid.HybridDecrypt)
    self.assertEqual(hybrid_dec.decrypt(ciphertext, context_info), plaintext)

  def test_serialize_parse_encrypted(self):
    keyset_encryption_aead = tink.new_keyset_handle(
        aead.aead_key_templates.AES128_GCM
    ).primitive(aead.Aead)

    keyset_encryption_associated_data = b'keyset_encryption_associated_data'
    keyset_handle = tink.new_keyset_handle(aead.aead_key_templates.AES128_GCM)
    encrypted_keyset = tink.json_proto_keyset_format.serialize_encrypted(
        keyset_handle, keyset_encryption_aead, keyset_encryption_associated_data
    )
    parsed_keyset_handle = tink.json_proto_keyset_format.parse_encrypted(
        encrypted_keyset,
        keyset_encryption_aead,
        keyset_encryption_associated_data,
    )

    # check that keyset_handle and parse_handle are the same.
    plaintext = b'plaintext'
    associated_data = b'associated_data'
    primitive1 = keyset_handle.primitive(aead.Aead)
    ciphertext = primitive1.encrypt(plaintext, associated_data)
    primitive2 = parsed_keyset_handle.primitive(aead.Aead)
    self.assertEqual(primitive2.decrypt(ciphertext, associated_data), plaintext)

    # check that it serialize and parse fail without secret_key_access.TOKEN
    with self.assertRaises(core.TinkError):
      tink.json_proto_keyset_format.parse_encrypted(
          encrypted_keyset,
          keyset_encryption_aead,
          b'invalid_associated_data',
      )

  def test_serialize_encrypted_read_keyset_handle_with_associated_data(self):
    keyset_encryption_aead = tink.new_keyset_handle(
        aead.aead_key_templates.AES128_GCM
    ).primitive(aead.Aead)

    keyset_encryption_associated_data = b'keyset_encryption_associated_data'
    keyset_handle = tink.new_keyset_handle(aead.aead_key_templates.AES128_GCM)
    encrypted_keyset = tink.json_proto_keyset_format.serialize_encrypted(
        keyset_handle,
        keyset_encryption_aead,
        keyset_encryption_associated_data,
    )

    reader = tink.JsonKeysetReader(encrypted_keyset)
    parsed_keyset_handle = tink.read_keyset_handle_with_associated_data(
        reader, keyset_encryption_aead, keyset_encryption_associated_data
    )

    # check that keyset_handle and parse_handle are the same.
    plaintext = b'plaintext'
    associated_data = b'associated_data'
    primitive1 = keyset_handle.primitive(aead.Aead)
    ciphertext = primitive1.encrypt(plaintext, associated_data)
    primitive2 = parsed_keyset_handle.primitive(aead.Aead)
    self.assertEqual(primitive2.decrypt(ciphertext, associated_data), plaintext)

  def test_write_with_associated_data_parse_encrypted(self):
    keyset_encryption_aead = tink.new_keyset_handle(
        aead.aead_key_templates.AES128_GCM
    ).primitive(aead.Aead)

    keyset_encryption_associated_data = b'keyset_encryption_associated_data'
    keyset_handle = tink.new_keyset_handle(aead.aead_key_templates.AES128_GCM)

    output_stream = io.StringIO()
    writer = tink.JsonKeysetWriter(output_stream)
    keyset_handle.write_with_associated_data(
        writer, keyset_encryption_aead, keyset_encryption_associated_data
    )
    encrypted_keyset = output_stream.getvalue()

    parsed_keyset_handle = tink.json_proto_keyset_format.parse_encrypted(
        encrypted_keyset,
        keyset_encryption_aead,
        keyset_encryption_associated_data,
    )

    # check that keyset_handle and parse_handle are the same.
    plaintext = b'plaintext'
    associated_data = b'associated_data'
    primitive1 = keyset_handle.primitive(aead.Aead)
    ciphertext = primitive1.encrypt(plaintext, associated_data)
    primitive2 = parsed_keyset_handle.primitive(aead.Aead)
    self.assertEqual(primitive2.decrypt(ciphertext, associated_data), plaintext)

  def test_serialize_encrypted_read_keyset_handle(self):
    keyset_encryption_aead = tink.new_keyset_handle(
        aead.aead_key_templates.AES128_GCM
    ).primitive(aead.Aead)

    # read_keyset_handle uses empty associated_data
    empty_keyset_encryption_associated_data = b''
    keyset_handle = tink.new_keyset_handle(aead.aead_key_templates.AES128_GCM)
    encrypted_keyset = tink.json_proto_keyset_format.serialize_encrypted(
        keyset_handle,
        keyset_encryption_aead,
        empty_keyset_encryption_associated_data,
    )

    reader = tink.JsonKeysetReader(encrypted_keyset)
    parsed_keyset_handle = tink.read_keyset_handle(
        reader, keyset_encryption_aead
    )

    # check that keyset_handle and parse_handle are the same.
    plaintext = b'plaintext'
    associated_data = b'associated_data'
    primitive1 = keyset_handle.primitive(aead.Aead)
    ciphertext = primitive1.encrypt(plaintext, associated_data)
    primitive2 = parsed_keyset_handle.primitive(aead.Aead)
    self.assertEqual(primitive2.decrypt(ciphertext, associated_data), plaintext)

  def test_write_parse_encrypted(self):
    keyset_encryption_aead = tink.new_keyset_handle(
        aead.aead_key_templates.AES128_GCM
    ).primitive(aead.Aead)

    keyset_handle = tink.new_keyset_handle(aead.aead_key_templates.AES128_GCM)

    output_stream = io.StringIO()
    writer = tink.JsonKeysetWriter(output_stream)
    keyset_handle.write(writer, keyset_encryption_aead)
    encrypted_keyset = output_stream.getvalue()

    # keyset_handle.write uses empty associated_data
    empty_keyset_encryption_associated_data = b''
    parsed_keyset_handle = tink.json_proto_keyset_format.parse_encrypted(
        encrypted_keyset,
        keyset_encryption_aead,
        empty_keyset_encryption_associated_data,
    )

    # check that keyset_handle and parse_handle are the same.
    plaintext = b'plaintext'
    associated_data = b'associated_data'
    primitive1 = keyset_handle.primitive(aead.Aead)
    ciphertext = primitive1.encrypt(plaintext, associated_data)
    primitive2 = parsed_keyset_handle.primitive(aead.Aead)
    self.assertEqual(primitive2.decrypt(ciphertext, associated_data), plaintext)


if __name__ == '__main__':
  absltest.main()
