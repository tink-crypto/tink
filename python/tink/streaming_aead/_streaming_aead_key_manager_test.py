# Copyright 2020 Google LLC
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
"""Tests for tink.python.tink.streaming_aead_key_manager."""

import io

from absl.testing import absltest
from absl.testing import parameterized
from tink.proto import aes_ctr_hmac_streaming_pb2
from tink.proto import aes_gcm_hkdf_streaming_pb2
from tink.proto import common_pb2
from tink.proto import tink_pb2
import tink
from tink import core
from tink import streaming_aead
from tink.streaming_aead import _raw_streaming_aead
from tink.testing import bytes_io

# Using malformed UTF-8 sequences to ensure there is no accidental decoding.
B_X80 = b'\x80'


def setUpModule():
  streaming_aead.register()


def new_raw_primitive():
  key_data = core.Registry.new_key_data(
      streaming_aead.streaming_aead_key_templates
      .AES128_CTR_HMAC_SHA256_4KB)
  return core.Registry.primitive(key_data,
                                 _raw_streaming_aead.RawStreamingAead)


class StreamingAeadKeyManagerTest(parameterized.TestCase):

  def test_new_aes_gcm_hkdf_key_data(self):
    key_template = (
        streaming_aead.streaming_aead_key_templates.AES128_GCM_HKDF_4KB)
    key_data = core.Registry.new_key_data(key_template)
    self.assertEqual(key_data.type_url, key_template.type_url)
    self.assertEqual(key_data.key_material_type, tink_pb2.KeyData.SYMMETRIC)
    key = aes_gcm_hkdf_streaming_pb2.AesGcmHkdfStreamingKey.FromString(
        key_data.value)
    self.assertEqual(key.version, 0)
    self.assertLen(key.key_value, 16)
    self.assertEqual(key.params.hkdf_hash_type, common_pb2.HashType.SHA256)
    self.assertEqual(key.params.derived_key_size, 16)
    self.assertEqual(key.params.ciphertext_segment_size, 4096)

  def test_new_aes_ctr_hmac_key_data(self):
    key_template = (
        streaming_aead.streaming_aead_key_templates.AES128_CTR_HMAC_SHA256_4KB)
    key_data = core.Registry.new_key_data(key_template)
    self.assertEqual(key_data.type_url, key_template.type_url)
    self.assertEqual(key_data.key_material_type, tink_pb2.KeyData.SYMMETRIC)
    key = aes_ctr_hmac_streaming_pb2.AesCtrHmacStreamingKey.FromString(
        key_data.value)
    self.assertEqual(key.version, 0)
    self.assertLen(key.key_value, 16)
    self.assertEqual(key.params.hkdf_hash_type, common_pb2.HashType.SHA256)
    self.assertEqual(key.params.derived_key_size, 16)
    self.assertEqual(key.params.hmac_params.hash, common_pb2.HashType.SHA256)
    self.assertEqual(key.params.hmac_params.tag_size, 32)
    self.assertEqual(key.params.ciphertext_segment_size, 4096)

  def test_invalid_aes_gcm_hkdf_params_throw_exception(self):
    tmpls = streaming_aead.streaming_aead_key_templates
    key_template = tmpls.create_aes_gcm_hkdf_streaming_key_template(
        63, common_pb2.HashType.SHA1, 65, 55)
    with self.assertRaisesRegex(core.TinkError,
                                'key_size must not be smaller than'):
      core.Registry.new_key_data(key_template)

  def test_invalid_aes_ctr_hmac_params_throw_exception(self):
    tmpls = streaming_aead.streaming_aead_key_templates
    key_template = tmpls.create_aes_ctr_hmac_streaming_key_template(
        63, common_pb2.HashType.SHA1, 65, common_pb2.HashType.SHA256, 55, 2)
    with self.assertRaisesRegex(core.TinkError,
                                'key_size must not be smaller than'):
      core.Registry.new_key_data(key_template)

  def test_raw_encrypt_decrypt_readall(self):
    raw_primitive = new_raw_primitive()
    plaintext = b'plaintext' + B_X80
    aad = b'associated_data' + B_X80

    # Encrypt
    ct_destination = bytes_io.BytesIOWithValueAfterClose()
    with raw_primitive.new_raw_encrypting_stream(ct_destination, aad) as es:
      self.assertLen(plaintext, es.write(plaintext))
    # context manager closes es, which also closes ciphertext_dest
    self.assertTrue(ct_destination.closed)

    # Decrypt, with and without close_ciphertext_source
    for close_ciphertext_source in [True, False]:
      ct_source = io.BytesIO(ct_destination.value_after_close())
      with raw_primitive.new_raw_decrypting_stream(
          ct_source, aad,
          close_ciphertext_source=close_ciphertext_source) as ds:
        output = ds.readall()
      self.assertEqual(ct_source.closed, close_ciphertext_source)
      self.assertEqual(output, plaintext)

  def test_raw_encrypt_decrypt_read(self):
    raw_primitive = new_raw_primitive()
    plaintext = b'plaintext'
    aad = b'aad'

    ct_destination = bytes_io.BytesIOWithValueAfterClose()
    with raw_primitive.new_raw_encrypting_stream(ct_destination, aad) as es:
      es.write(plaintext)

    ct_source = io.BytesIO(ct_destination.value_after_close())
    with raw_primitive.new_raw_decrypting_stream(
        ct_source, aad, close_ciphertext_source=True) as ds:
      self.assertEqual(ds.read(5), b'plain')
      self.assertEqual(ds.read(5), b'text')

  def test_raw_encrypt_decrypt_readinto(self):
    raw_primitive = new_raw_primitive()
    plaintext = b'plaintext'
    aad = b'aad'

    ct_destination = bytes_io.BytesIOWithValueAfterClose()
    with raw_primitive.new_raw_encrypting_stream(ct_destination, aad) as es:
      es.write(plaintext)

    ct_source = io.BytesIO(ct_destination.value_after_close())
    with raw_primitive.new_raw_decrypting_stream(
        ct_source, aad, close_ciphertext_source=True) as ds:
      data = bytearray(b'xxxxx')
      n = ds.readinto(data)  # writes 5 bytes into data.
      self.assertEqual(n, 5)
      self.assertEqual(data, b'plain')
      n = ds.readinto(data)  # writes remaining 4 bytes, leave the rest
      self.assertEqual(n, 4)
      self.assertEqual(data, b'textn')

  def test_raw_encrypt_decrypt_empty(self):
    raw_primitive = new_raw_primitive()
    plaintext = b''
    aad = b''
    ct_destination = bytes_io.BytesIOWithValueAfterClose()
    with raw_primitive.new_raw_encrypting_stream(ct_destination, aad) as es:
      es.write(plaintext)

    ct_source = io.BytesIO(ct_destination.value_after_close())
    with raw_primitive.new_raw_decrypting_stream(
        ct_source, aad, close_ciphertext_source=True) as ds:
      self.assertEqual(ds.read(5), b'')

  def test_raw_read_after_eof_returns_empty_bytes(self):
    raw_primitive = new_raw_primitive()
    plaintext = b'plaintext' + B_X80
    aad = b'associated_data' + B_X80

    ct_destination = bytes_io.BytesIOWithValueAfterClose()
    with raw_primitive.new_raw_encrypting_stream(ct_destination, aad) as es:
      self.assertLen(plaintext, es.write(plaintext))

    ct_source = io.BytesIO(ct_destination.value_after_close())
    with raw_primitive.new_raw_decrypting_stream(
        ct_source, aad, close_ciphertext_source=True) as ds:
      _ = ds.readall()
      self.assertEqual(ds.read(100), b'')

  def test_raw_encrypt_decrypt_close(self):
    raw_primitive = new_raw_primitive()
    plaintext = b'plaintext' + B_X80
    aad = b'associated_data' + B_X80

    # Encrypt
    ct_destination = bytes_io.BytesIOWithValueAfterClose()
    es = raw_primitive.new_raw_encrypting_stream(ct_destination, aad)
    es.write(plaintext)
    self.assertFalse(ct_destination.closed)
    self.assertFalse(es.closed)
    es.close()
    self.assertTrue(ct_destination.closed)
    self.assertTrue(es.closed)

    # Decrypt, with and without close_ciphertext_source
    for close_ciphertext_source in [True, False]:
      ct_source = io.BytesIO(ct_destination.value_after_close())
      ds = raw_primitive.new_raw_decrypting_stream(
          ct_source, aad,
          close_ciphertext_source=close_ciphertext_source)
      self.assertFalse(ct_source.closed)
      self.assertFalse(ds.closed)
      ds.close()
      self.assertEqual(ct_source.closed, close_ciphertext_source)
      self.assertTrue(ds.closed)

  def test_raw_encrypt_decrypt_wrong_aad(self):
    raw_primitive = new_raw_primitive()
    plaintext = b'plaintext' + B_X80
    aad = b'associated_data' + B_X80

    # Encrypt
    ct_destination = bytes_io.BytesIOWithValueAfterClose()
    with raw_primitive.new_raw_encrypting_stream(ct_destination, aad) as es:
      self.assertLen(plaintext, es.write(plaintext))
    self.assertNotEqual(ct_destination.value_after_close(), plaintext)

    # Decrypt
    ct_source = io.BytesIO(ct_destination.value_after_close())
    with raw_primitive.new_raw_decrypting_stream(
        ct_source, b'bad' + aad, close_ciphertext_source=True) as ds:
      with self.assertRaises(core.TinkError):
        ds.read()

  @parameterized.parameters([
      streaming_aead.streaming_aead_key_templates.AES128_GCM_HKDF_4KB,
      streaming_aead.streaming_aead_key_templates.AES128_GCM_HKDF_1MB,
      streaming_aead.streaming_aead_key_templates.AES256_GCM_HKDF_4KB,
      streaming_aead.streaming_aead_key_templates.AES256_GCM_HKDF_1MB,
      streaming_aead.streaming_aead_key_templates.AES128_CTR_HMAC_SHA256_4KB,
      streaming_aead.streaming_aead_key_templates.AES128_CTR_HMAC_SHA256_1MB,
      streaming_aead.streaming_aead_key_templates.AES256_CTR_HMAC_SHA256_4KB,
      streaming_aead.streaming_aead_key_templates.AES256_CTR_HMAC_SHA256_1MB
  ])
  def test_encrypt_decrypt_success(self, template):
    keyset_handle = tink.new_keyset_handle(template)
    primitive = keyset_handle.primitive(streaming_aead.StreamingAead)

    plaintext = b'plaintext'
    associated_data = b'associated_data'

    # Encrypt
    ciphertext_destination = bytes_io.BytesIOWithValueAfterClose()
    with primitive.new_encrypting_stream(ciphertext_destination,
                                         associated_data) as encryption_stream:
      encryption_stream.write(plaintext)

    ciphertext = ciphertext_destination.value_after_close()

    # Decrypt
    ciphertext_source = io.BytesIO(ciphertext)
    decrypted = None
    with primitive.new_decrypting_stream(ciphertext_source,
                                         associated_data) as decryption_stream:
      decrypted = decryption_stream.read()

    self.assertEqual(decrypted, plaintext)

if __name__ == '__main__':
  absltest.main()
