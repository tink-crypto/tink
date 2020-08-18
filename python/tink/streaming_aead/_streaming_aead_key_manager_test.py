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
"""Tests for tink.python.tink.streaming_aead_key_manager."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import io
import os
import tempfile
from typing import BinaryIO, cast

from absl.testing import absltest
from tink.proto import aes_ctr_hmac_streaming_pb2
from tink.proto import aes_gcm_hkdf_streaming_pb2
from tink.proto import common_pb2
from tink.proto import tink_pb2
from tink import core
from tink import streaming_aead
from tink.streaming_aead import _raw_streaming_aead
from tink.testing import bytes_io

# Using malformed UTF-8 sequences to ensure there is no accidental decoding.
B_X80 = b'\x80'


def setUpModule():
  streaming_aead.register()


class StreamingAeadKeyManagerTest(absltest.TestCase):

  def setUp(self):
    super(StreamingAeadKeyManagerTest, self).setUp()
    self.key_manager_gcm = streaming_aead.key_manager_from_cc_registry(
        'type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey')
    self.key_manager_ctr = streaming_aead.key_manager_from_cc_registry(
        'type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey')

  def test_primitive_class(self):
    self.assertEqual(self.key_manager_gcm.primitive_class(),
                     _raw_streaming_aead.RawStreamingAead)
    self.assertEqual(self.key_manager_ctr.primitive_class(),
                     _raw_streaming_aead.RawStreamingAead)

  def test_key_type(self):
    self.assertEqual(
        self.key_manager_gcm.key_type(),
        'type.googleapis.com/google.crypto.tink.AesGcmHkdfStreamingKey')
    self.assertEqual(
        self.key_manager_ctr.key_type(),
        'type.googleapis.com/google.crypto.tink.AesCtrHmacStreamingKey')

  def test_new_aes_gcm_hkdf_key_data(self):
    key_template = streaming_aead.streaming_aead_key_templates.AES128_GCM_HKDF_4KB
    key_data = self.key_manager_gcm.new_key_data(key_template)
    self.assertEqual(key_data.type_url, self.key_manager_gcm.key_type())
    self.assertEqual(key_data.key_material_type, tink_pb2.KeyData.SYMMETRIC)
    key = aes_gcm_hkdf_streaming_pb2.AesGcmHkdfStreamingKey()
    key.ParseFromString(key_data.value)
    self.assertEqual(key.version, 0)
    self.assertLen(key.key_value, 16)
    self.assertEqual(key.params.hkdf_hash_type, common_pb2.HashType.SHA256)
    self.assertEqual(key.params.derived_key_size, 16)
    self.assertEqual(key.params.ciphertext_segment_size, 4096)

  def test_new_aes_ctr_hmac_key_data(self):
    key_template = streaming_aead.streaming_aead_key_templates.AES128_CTR_HMAC_SHA256_4KB
    key_data = self.key_manager_ctr.new_key_data(key_template)
    self.assertEqual(key_data.type_url, self.key_manager_ctr.key_type())
    self.assertEqual(key_data.key_material_type, tink_pb2.KeyData.SYMMETRIC)
    key = aes_ctr_hmac_streaming_pb2.AesCtrHmacStreamingKey()
    key.ParseFromString(key_data.value)
    self.assertEqual(key.version, 0)
    self.assertLen(key.key_value, 16)
    self.assertEqual(key.params.hkdf_hash_type, common_pb2.HashType.SHA256)
    self.assertEqual(key.params.derived_key_size, 16)
    self.assertEqual(key.params.hmac_params.hash, common_pb2.HashType.SHA256)
    self.assertEqual(key.params.hmac_params.tag_size, 32)
    self.assertEqual(key.params.ciphertext_segment_size, 4096)

  def test_invalid_aes_gcm_hkdf_params_throw_exception(self):
    key_template = streaming_aead.streaming_aead_key_templates.create_aes_gcm_hkdf_streaming_key_template(
        63, common_pb2.HashType.SHA1, 65, 55)
    with self.assertRaisesRegex(core.TinkError,
                                'key_size must not be smaller than'):
      self.key_manager_gcm.new_key_data(key_template)

  def test_invalid_aes_ctr_hmac_params_throw_exception(self):
    key_template = streaming_aead.streaming_aead_key_templates.create_aes_ctr_hmac_streaming_key_template(
        63, common_pb2.HashType.SHA1, 65, common_pb2.HashType.SHA256, 55, 2)
    with self.assertRaisesRegex(core.TinkError,
                                'key_size must not be smaller than'):
      self.key_manager_ctr.new_key_data(key_template)

  def test_encrypt_decrypt_raw(self):
    raw_primitive = self.key_manager_ctr.primitive(
        self.key_manager_ctr.new_key_data(
            streaming_aead.streaming_aead_key_templates
            .AES128_CTR_HMAC_SHA256_4KB))
    plaintext = b'plaintext' + B_X80
    aad = b'associated_data' + B_X80

    # Encrypt
    ct_destination = bytes_io.BytesIOWithValueAfterClose()
    with raw_primitive.new_raw_encrypting_stream(ct_destination, aad) as es:
      self.assertLen(plaintext, es.write(plaintext))
    # context manager closes es, which also closes ciphertext_dest
    self.assertTrue(ct_destination.closed)

    # Decrypt
    ct_source = io.BytesIO(ct_destination.value_after_close())
    with raw_primitive.new_raw_decrypting_stream(ct_source, aad) as ds:
      output = ds.readall()
    # context manager closes ds, which also closes ct_source
    self.assertTrue(ct_source.closed)
    self.assertEqual(output, plaintext)

  def test_read_after_eof_returns_empty_bytes(self):
    raw_primitive = self.key_manager_ctr.primitive(
        self.key_manager_ctr.new_key_data(
            streaming_aead.streaming_aead_key_templates
            .AES128_CTR_HMAC_SHA256_4KB))
    plaintext = b'plaintext' + B_X80
    aad = b'associated_data' + B_X80

    ct_destination = bytes_io.BytesIOWithValueAfterClose()
    with raw_primitive.new_raw_encrypting_stream(ct_destination, aad) as es:
      self.assertLen(plaintext, es.write(plaintext))

    ct_source = io.BytesIO(ct_destination.value_after_close())
    with raw_primitive.new_raw_decrypting_stream(ct_source, aad) as ds:
      _ = ds.readall()
      self.assertEqual(ds.read(100), b'')

  def test_encrypt_decrypt_tempfile(self):
    raw_primitive = self.key_manager_ctr.primitive(
        self.key_manager_ctr.new_key_data(
            streaming_aead.streaming_aead_key_templates
            .AES128_CTR_HMAC_SHA256_4KB))
    plaintext = b'plaintext'
    aad = b'associated_data'

    ciphertext_dest = cast(BinaryIO,
                           tempfile.NamedTemporaryFile('wb', delete=False))
    encryptedfile_name = ciphertext_dest.name
    with raw_primitive.new_raw_encrypting_stream(ciphertext_dest, aad) as es:
      n = es.write(plaintext)
    self.assertTrue(ciphertext_dest.closed)
    self.assertLen(plaintext, n)

    ciphertext_src = open(encryptedfile_name, 'rb')
    with raw_primitive.new_raw_decrypting_stream(ciphertext_src, aad) as ds:
      output = ds.readall()
    self.assertTrue(ciphertext_src.closed)
    os.unlink(encryptedfile_name)
    self.assertEqual(output, plaintext)

  def test_encrypt_decrypt_wrong_aad(self):
    raw_primitive = self.key_manager_ctr.primitive(
        self.key_manager_ctr.new_key_data(
            streaming_aead.streaming_aead_key_templates
            .AES128_CTR_HMAC_SHA256_4KB))
    plaintext = b'plaintext' + B_X80
    aad = b'associated_data' + B_X80

    # Encrypt
    ct_destination = bytes_io.BytesIOWithValueAfterClose()
    with raw_primitive.new_raw_encrypting_stream(ct_destination, aad) as es:
      self.assertLen(plaintext, es.write(plaintext))
    self.assertNotEqual(ct_destination.value_after_close(), plaintext)

    # Decrypt
    ct_source = io.BytesIO(ct_destination.value_after_close())
    with raw_primitive.new_raw_decrypting_stream(ct_source, b'bad' + aad) as ds:
      with self.assertRaises(core.TinkError):
        ds.read()


if __name__ == '__main__':
  absltest.main()
