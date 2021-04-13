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
"""Tests for tink.python.tink.streaming_aead._streaming_aead_wrapper."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import io
from typing import BinaryIO, cast

from absl.testing import absltest
from absl.testing import parameterized
import tink
from tink import streaming_aead
from tink.testing import bytes_io
from tink.testing import keyset_builder


TEMPLATE = streaming_aead.streaming_aead_key_templates.AES128_GCM_HKDF_4KB


def setUpModule():
  streaming_aead.register()


def _encrypt(primitive: streaming_aead.StreamingAead, plaintext: bytes,
             associated_data: bytes) -> bytes:
  ciphertext_dest = bytes_io.BytesIOWithValueAfterClose()
  with primitive.new_encrypting_stream(ciphertext_dest, associated_data) as es:
    es.write(plaintext)
  return ciphertext_dest.value_after_close()


class StreamingAeadWrapperTest(parameterized.TestCase):

  @parameterized.parameters(
      [b'plaintext', b'', b'smile \xf0\x9f\x98\x80', b'\xf0\x9f\x98'])
  def test_encrypt_decrypt_success(self, plaintext):
    keyset_handle = tink.new_keyset_handle(TEMPLATE)
    primitive = keyset_handle.primitive(streaming_aead.StreamingAead)

    aad = b'associated_data'
    ciphertext_dest = bytes_io.BytesIOWithValueAfterClose()
    with primitive.new_encrypting_stream(ciphertext_dest, aad) as es:
      self.assertLen(plaintext, es.write(plaintext))
    self.assertTrue(ciphertext_dest.closed)

    ciphertext_src = io.BytesIO(ciphertext_dest.value_after_close())
    with primitive.new_decrypting_stream(ciphertext_src, aad) as ds:
      output = ds.read()
    self.assertTrue(ciphertext_src.closed)
    self.assertEqual(output, plaintext)

  def test_long_plaintext_encrypt_decrypt_success(self):
    keyset_handle = tink.new_keyset_handle(TEMPLATE)
    primitive = keyset_handle.primitive(streaming_aead.StreamingAead)

    long_plaintext = b' '.join(b'%d' % i for i in range(10 * 1000 * 1000))
    aad = b'associated_data'
    ciphertext_dest = bytes_io.BytesIOWithValueAfterClose()
    with primitive.new_encrypting_stream(ciphertext_dest, aad) as es:
      self.assertLen(long_plaintext, es.write(long_plaintext))
    self.assertTrue(ciphertext_dest.closed)

    ciphertext_src = io.BytesIO(ciphertext_dest.value_after_close())
    with primitive.new_decrypting_stream(ciphertext_src, aad) as ds:
      output = ds.read()
    self.assertTrue(ciphertext_src.closed)
    self.assertEqual(output, long_plaintext)

  @parameterized.parameters(
      [bytes_io.SlowBytesIO, bytes_io.SlowReadableRawBytes])
  def test_slow_encrypt_decrypt_success(self, input_stream_factory):
    keyset_handle = tink.new_keyset_handle(TEMPLATE)
    primitive = keyset_handle.primitive(streaming_aead.StreamingAead)
    plaintext = b' '.join(b'%d' % i for i in range(10 * 1000))
    aad = b'associated_data'
    ciphertext = _encrypt(primitive, plaintext, aad)

    # Even if the ciphertext source only returns small data chunks and sometimes
    # None, calling read() should return the whole ciphertext.
    ciphertext_src = cast(BinaryIO, input_stream_factory(ciphertext))
    with primitive.new_decrypting_stream(ciphertext_src, aad) as ds:
      output = ds.read()
    self.assertTrue(ciphertext_src.closed)
    self.assertEqual(output, plaintext)

  def test_encrypt_decrypt_bad_aad(self):
    keyset_handle = tink.new_keyset_handle(TEMPLATE)
    primitive = keyset_handle.primitive(streaming_aead.StreamingAead)

    plaintext = b'plaintext'
    aad = b'associated_data'

    ciphertext_dest = bytes_io.BytesIOWithValueAfterClose()
    with primitive.new_encrypting_stream(ciphertext_dest, aad) as es:
      self.assertLen(plaintext, es.write(plaintext))
    self.assertTrue(ciphertext_dest.closed)

    ciphertext_src = io.BytesIO(ciphertext_dest.value_after_close())
    with primitive.new_decrypting_stream(ciphertext_src, b'bad aad') as ds:
      with self.assertRaises(tink.TinkError):
        _ = ds.read()

  def test_decrypt_unknown_key_fails(self):
    plaintext = b'plaintext'
    aad = b'associated_data'

    unknown_keyset_handle = tink.new_keyset_handle(TEMPLATE)
    unknown_primitive = unknown_keyset_handle.primitive(
        streaming_aead.StreamingAead)
    unknown_ciphertext_dest = bytes_io.BytesIOWithValueAfterClose()
    with unknown_primitive.new_encrypting_stream(unknown_ciphertext_dest,
                                                 aad) as es:
      es.write(plaintext)

    keyset_handle = tink.new_keyset_handle(TEMPLATE)
    primitive = keyset_handle.primitive(streaming_aead.StreamingAead)
    ciphertext_src = io.BytesIO(unknown_ciphertext_dest.value_after_close())
    with primitive.new_decrypting_stream(ciphertext_src, aad) as ds:
      with self.assertRaises(tink.TinkError):
        _ = ds.read()

  @parameterized.parameters(
      [io.BytesIO, bytes_io.SlowBytesIO, bytes_io.SlowReadableRawBytes])
  def test_encrypt_decrypt_with_key_rotation(self, input_stream_factory):
    builder = keyset_builder.new_keyset_builder()
    older_key_id = builder.add_new_key(TEMPLATE)
    builder.set_primary_key(older_key_id)
    p1 = builder.keyset_handle().primitive(streaming_aead.StreamingAead)

    newer_key_id = builder.add_new_key(TEMPLATE)
    p2 = builder.keyset_handle().primitive(streaming_aead.StreamingAead)

    builder.set_primary_key(newer_key_id)
    p3 = builder.keyset_handle().primitive(streaming_aead.StreamingAead)

    builder.disable_key(older_key_id)
    p4 = builder.keyset_handle().primitive(streaming_aead.StreamingAead)

    self.assertNotEqual(older_key_id, newer_key_id)

    # p1 encrypts with the older key. So p1, p2 and p3 can decrypt it,
    # but not p4.
    plaintext1 = b' '.join(b'%d' % i for i in range(100 * 101))
    ciphertext1 = _encrypt(p1, plaintext1, b'aad1')
    with p1.new_decrypting_stream(
        cast(BinaryIO, input_stream_factory(ciphertext1)), b'aad1') as ds:
      self.assertEqual(ds.read(), plaintext1)
    with p2.new_decrypting_stream(
        cast(BinaryIO, input_stream_factory(ciphertext1)), b'aad1') as ds:
      self.assertEqual(ds.read(), plaintext1)
    with p3.new_decrypting_stream(
        cast(BinaryIO, input_stream_factory(ciphertext1)), b'aad1') as ds:
      self.assertEqual(ds.read(), plaintext1)
    with p4.new_decrypting_stream(
        cast(BinaryIO, input_stream_factory(ciphertext1)), b'aad1') as ds:
      with self.assertRaises(tink.TinkError):
        ds.read()

    # p2 encrypts with the older key. So p1, p2 and p3 can decrypt it,
    # but not p4.
    plaintext2 = b' '.join(b'%d' % i for i in range(100 * 102))
    ciphertext2 = _encrypt(p2, plaintext2, b'aad2')
    with p1.new_decrypting_stream(
        cast(BinaryIO, input_stream_factory(ciphertext2)), b'aad2') as ds:
      self.assertEqual(ds.read(), plaintext2)
    with p2.new_decrypting_stream(
        cast(BinaryIO, input_stream_factory(ciphertext2)), b'aad2') as ds:
      self.assertEqual(ds.read(), plaintext2)
    with p3.new_decrypting_stream(
        cast(BinaryIO, input_stream_factory(ciphertext2)), b'aad2') as ds:
      self.assertEqual(ds.read(), plaintext2)
    with p4.new_decrypting_stream(
        cast(BinaryIO, input_stream_factory(ciphertext2)), b'aad2') as ds:
      with self.assertRaises(tink.TinkError):
        ds.read()

    # p3 encrypts with the newer key. So p2, p3 and p4 can decrypt it,
    # but not p1.
    plaintext3 = b' '.join(b'%d' % i for i in range(100 * 103))
    ciphertext3 = _encrypt(p3, plaintext3, b'aad3')
    with p1.new_decrypting_stream(
        cast(BinaryIO, input_stream_factory(ciphertext3)), b'aad3') as ds:
      with self.assertRaises(tink.TinkError):
        ds.read()
    with p2.new_decrypting_stream(
        cast(BinaryIO, input_stream_factory(ciphertext3)), b'aad3') as ds:
      self.assertEqual(ds.read(), plaintext3)
    with p3.new_decrypting_stream(
        cast(BinaryIO, input_stream_factory(ciphertext3)), b'aad3') as ds:
      self.assertEqual(ds.read(), plaintext3)
    with p4.new_decrypting_stream(
        cast(BinaryIO, input_stream_factory(ciphertext3)), b'aad3') as ds:
      self.assertEqual(ds.read(), plaintext3)

    # p4 encrypts with the newer key. So p2, p3 and p4 can decrypt it,
    # but not p1.
    plaintext4 = b' '.join(b'%d' % i for i in range(100 * 104))
    ciphertext4 = _encrypt(p4, plaintext4, b'aad4')
    with p1.new_decrypting_stream(
        cast(BinaryIO, input_stream_factory(ciphertext4)), b'aad4') as ds:
      with self.assertRaises(tink.TinkError):
        ds.read()
    with p2.new_decrypting_stream(
        cast(BinaryIO, input_stream_factory(ciphertext4)), b'aad4') as ds:
      self.assertEqual(ds.read(), plaintext4)
    with p3.new_decrypting_stream(
        cast(BinaryIO, input_stream_factory(ciphertext4)), b'aad4') as ds:
      self.assertEqual(ds.read(), plaintext4)
    with p4.new_decrypting_stream(
        cast(BinaryIO, input_stream_factory(ciphertext4)), b'aad4') as ds:
      self.assertEqual(ds.read(), plaintext4)


if __name__ == '__main__':
  absltest.main()
