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
from typing import BinaryIO, cast

from absl.testing import absltest
from absl.testing import parameterized
from tink.proto import aes_ctr_hmac_streaming_pb2
from tink.proto import aes_gcm_hkdf_streaming_pb2
from tink.proto import common_pb2
from tink.proto import tink_pb2
import tink
from tink import cleartext_keyset_handle
from tink import core
from tink import streaming_aead
from tink.streaming_aead import _raw_streaming_aead
from tink.testing import bytes_io

# Using malformed UTF-8 sequences to ensure there is no accidental decoding.
B_X80 = b'\x80'


def setUpModule():
  streaming_aead.register()


class StreamingAeadKeyManagerTest(parameterized.TestCase):

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

  def test_raw_encrypt_decrypt(self):
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

    # Decrypt, with and without close_ciphertext_source
    for close_ciphertext_source in [True, False]:
      ct_source = io.BytesIO(ct_destination.value_after_close())
      with raw_primitive.new_raw_decrypting_stream(
          ct_source, aad,
          close_ciphertext_source=close_ciphertext_source) as ds:
        output = ds.readall()
      self.assertEqual(ct_source.closed, close_ciphertext_source)
      self.assertEqual(output, plaintext)

  def test_raw_read_after_eof_returns_empty_bytes(self):
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
    with raw_primitive.new_raw_decrypting_stream(
        ct_source, aad, close_ciphertext_source=True) as ds:
      _ = ds.readall()
      self.assertEqual(ds.read(100), b'')

  def test_raw_encrypt_decrypt_wrong_aad(self):
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
    with raw_primitive.new_raw_decrypting_stream(
        ct_source, b'bad' + aad, close_ciphertext_source=True) as ds:
      with self.assertRaises(core.TinkError):
        ds.read()

  @parameterized.parameters(
      [io.BytesIO, bytes_io.SlowBytesIO, bytes_io.SlowReadableRawBytes])
  def test_wrapped_encrypt_decrypt_two_keys(self, input_stream_factory):
    template = (
        streaming_aead.streaming_aead_key_templates.AES128_CTR_HMAC_SHA256_4KB)
    old_keyset = tink_pb2.Keyset()
    key1 = old_keyset.key.add()
    key1.key_data.CopyFrom(tink.core.Registry.new_key_data(template))
    key1.status = tink_pb2.ENABLED
    key1.key_id = 1234
    key1.output_prefix_type = template.output_prefix_type
    old_keyset.primary_key_id = key1.key_id
    old_keyset_handle = cleartext_keyset_handle.from_keyset(old_keyset)
    old_primitive = old_keyset_handle.primitive(streaming_aead.StreamingAead)

    new_keyset = tink_pb2.Keyset()
    new_keyset.CopyFrom(old_keyset)
    key2 = new_keyset.key.add()
    key2.key_data.CopyFrom(tink.core.Registry.new_key_data(template))
    key2.status = tink_pb2.ENABLED
    key2.key_id = 5678
    key2.output_prefix_type = template.output_prefix_type
    new_keyset.primary_key_id = key2.key_id
    new_keyset_handle = cleartext_keyset_handle.from_keyset(new_keyset)
    new_primitive = new_keyset_handle.primitive(streaming_aead.StreamingAead)

    plaintext1 = b' '.join(b'%d' % i for i in range(100 * 1000))
    ciphertext1_dest = bytes_io.BytesIOWithValueAfterClose()
    with old_primitive.new_encrypting_stream(ciphertext1_dest, b'aad1') as es:
      es.write(plaintext1)
    ciphertext1 = ciphertext1_dest.value_after_close()

    plaintext2 = b' '.join(b'%d' % i for i in range(100 * 1001))
    ciphertext2_dest = bytes_io.BytesIOWithValueAfterClose()
    with new_primitive.new_encrypting_stream(ciphertext2_dest, b'aad2') as es:
      es.write(plaintext2)
    ciphertext2 = ciphertext2_dest.value_after_close()

    # old_primitive can read 1st ciphertext, but not the 2nd
    with old_primitive.new_decrypting_stream(
        cast(BinaryIO, input_stream_factory(ciphertext1)), b'aad1') as ds:
      self.assertEqual(ds.read(), plaintext1)
    with old_primitive.new_decrypting_stream(
        cast(BinaryIO, input_stream_factory(ciphertext2)), b'aad2') as ds:
      with self.assertRaises(tink.TinkError):
        ds.read()

    # new_primitive can read both ciphertexts
    with new_primitive.new_decrypting_stream(
        cast(BinaryIO, input_stream_factory(ciphertext1)), b'aad1') as ds:
      self.assertEqual(ds.read(), plaintext1)
    with new_primitive.new_decrypting_stream(
        cast(BinaryIO, input_stream_factory(ciphertext2)), b'aad2') as ds:
      self.assertEqual(ds.read(), plaintext2)

if __name__ == '__main__':
  absltest.main()
