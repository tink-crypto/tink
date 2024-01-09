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

"""Tests for tink.python.tink.proto_keyset_format."""

import io

from absl.testing import absltest

import tink
from tink import aead
from tink import core
from tink import hybrid
from tink import mac
from tink import secret_key_access
from tink import tink_config


def setUpModule():
  tink_config.register()


class InvalidKeyAccess(core.KeyAccess):
  pass


class TinkProtoKeysetFormatTest(absltest.TestCase):

  def test_serialize_parse(self):
    keyset_handle = tink.new_keyset_handle(aead.aead_key_templates.AES128_GCM)
    serialized_keyset = tink.proto_keyset_format.serialize(
        keyset_handle, secret_key_access.TOKEN
    )
    parsed_keyset_handle = tink.proto_keyset_format.parse(
        serialized_keyset, secret_key_access.TOKEN
    )

    # check that keyset_handle and parse_handle are the same.
    plaintext = b'plaintext'
    associated_data = b'associated_data'
    primitive1 = keyset_handle.primitive(aead.Aead)
    ciphertext = primitive1.encrypt(plaintext, associated_data)
    primitive2 = parsed_keyset_handle.primitive(aead.Aead)
    self.assertEqual(primitive2.decrypt(ciphertext, associated_data), plaintext)

    # check that serialize and parse fail without secret_key_access.TOKEN
    with self.assertRaises(core.TinkError):
      tink.proto_keyset_format.serialize(keyset_handle, InvalidKeyAccess())
    with self.assertRaises(core.TinkError):
      tink.proto_keyset_format.parse(serialized_keyset, InvalidKeyAccess())

  def test_serialize_parse_without_secret(self):
    private_handle = tink.new_keyset_handle(
        hybrid.hybrid_key_templates.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM
    )
    public_handle = private_handle.public_keyset_handle()

    # serialize and parse public_handle
    serialized = tink.proto_keyset_format.serialize_without_secret(
        public_handle
    )
    parsed = tink.proto_keyset_format.parse_without_secret(serialized)

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
    encrypted_keyset = tink.proto_keyset_format.serialize_encrypted(
        keyset_handle, keyset_encryption_aead, keyset_encryption_associated_data
    )
    parsed_keyset_handle = tink.proto_keyset_format.parse_encrypted(
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

    with self.assertRaises(core.TinkError):
      tink.proto_keyset_format.parse_encrypted(
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
    encrypted_keyset = tink.proto_keyset_format.serialize_encrypted(
        keyset_handle,
        keyset_encryption_aead,
        keyset_encryption_associated_data,
    )

    reader = tink.BinaryKeysetReader(encrypted_keyset)
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

    output_stream = io.BytesIO()
    writer = tink.BinaryKeysetWriter(output_stream)
    keyset_handle.write_with_associated_data(
        writer, keyset_encryption_aead, keyset_encryption_associated_data
    )
    encrypted_keyset = output_stream.getvalue()

    parsed_keyset_handle = tink.proto_keyset_format.parse_encrypted(
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
    encrypted_keyset = tink.proto_keyset_format.serialize_encrypted(
        keyset_handle,
        keyset_encryption_aead,
        empty_keyset_encryption_associated_data,
    )

    reader = tink.BinaryKeysetReader(encrypted_keyset)
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

    output_stream = io.BytesIO()
    writer = tink.BinaryKeysetWriter(output_stream)
    keyset_handle.write(writer, keyset_encryption_aead)
    encrypted_keyset = output_stream.getvalue()

    # keyset_handle.write uses empty associated_data
    empty_keyset_encryption_associated_data = b''
    parsed_keyset_handle = tink.proto_keyset_format.parse_encrypted(
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

  def test_parse_keyset_from_test_vector(self):
    # Same as in TinkProtoKeysetFormatTest.parseKeysetFromTestVector.
    # It contains one HMAC key.
    serialized_keyset = bytes.fromhex(
        '0895e59bcc0612680a5c0a2e747970652e676f6f676c65617069732e636f6d2f676f6f'
        '676c652e63727970746f2e74696e6b2e486d61634b657912281a20cca20f02278003b3'
        '513f5d01759ac1302f7d883f2f4a40025532ee1b11f9e5871204101008031801100118'
        '95e59bcc062001'
    )
    parsed_keyset_handle = tink.proto_keyset_format.parse(
        serialized_keyset, secret_key_access.TOKEN
    )
    primitive = parsed_keyset_handle.primitive(mac.Mac)
    valid_mac = bytes.fromhex('016986f2956092d259136923c6f4323557714ec499')
    data = b'data'
    primitive.verify_mac(valid_mac, data)

  def test_parse_encrypted_keyset_from_test_vector(self):
    # Same as in TinkProtoKeysetFormatTest.parseEncryptedKeysetFromTestVector.
    # An AEAD key, with which we encrypted the mac keyset below.
    serialized_keyset_encryption_keyset = bytes.fromhex(
        '08b891f5a20412580a4c0a30747970652e676f6f676c65617069732e636f6d2f676f6f'
        '676c652e63727970746f2e74696e6b2e4165734561784b65791216120208101a10e5d7'
        'd0cdd649e81e7952260689b2e1971801100118b891f5a2042001'
    )
    keyset_encryption_handle = tink.proto_keyset_format.parse(
        serialized_keyset_encryption_keyset, secret_key_access.TOKEN
    )
    keyset_encryption_aead = keyset_encryption_handle.primitive(aead.Aead)

    # A keyset that contains one HMAC key, encrypted with the above, using
    # associatedData
    encrypted_serialized_keyset = bytes.fromhex(
        '12950101445d48b8b5f591efaf73a46df9ebd7b6ac471cc0cf4f815a4f012fcaffc8f0'
        'b2b10b30c33194f0b291614bd8e1d2e80118e5d6226b6c41551e104ef8cd8ee20f1c14'
        'c1b87f6eed5fb04a91feafaacbf6f368519f36f97f7d08b24c8e71b5e620c4f69615ef'
        '0479391666e2fb32e46b416893fc4e564ba927b22ebff2a77bd3b5b8d5afa162cbd35c'
        '94c155cdfa13c8a9c964cde21a4208f5909ce901123a0a2e747970652e676f6f676c65'
        '617069732e636f6d2f676f6f676c652e63727970746f2e74696e6b2e486d61634b6579'
        '100118f5909ce9012001'
    )
    associated_data = bytes.fromhex('abcdef330012')

    handle = tink.proto_keyset_format.parse_encrypted(
        encrypted_serialized_keyset,
        keyset_encryption_aead,
        associated_data,
    )

    primitive = handle.primitive(mac.Mac)
    message = b''
    tag = bytes.fromhex('011d270875989dd6fbd5f54dbc9520bb41efd058d5')
    primitive.verify_mac(tag, message)

  def test_encrypted_keyset_overhead(self):
    keyset_encryption_aead = tink.new_keyset_handle(
        aead.aead_key_templates.AES128_GCM
    ).primitive(aead.Aead)

    keyset_handle = tink.new_keyset_handle(aead.aead_key_templates.AES128_GCM)

    serialized_keyset = tink.proto_keyset_format.serialize(
        keyset_handle, secret_key_access.TOKEN
    )
    raw_encrypted_keyset = keyset_encryption_aead.encrypt(
        serialized_keyset, b''
    )

    encrypted_keyset = tink.proto_keyset_format.serialize_encrypted(
        keyset_handle=keyset_handle,
        keyset_encryption_aead=keyset_encryption_aead,
        associated_data=b'',
    )
    # encrypted_keyset is a serialized protocol buffer that contains only
    # raw_encrypted_keyset in a field. So
    # it should only be slightly larger than raw_encrypted_keyset.
    # The overhead is currently just 2 bytes, but we choose 6 here to avoid
    # making the test brittle or flaky.
    self.assertLessEqual(len(encrypted_keyset), len(raw_encrypted_keyset) + 6)


if __name__ == '__main__':
  absltest.main()
