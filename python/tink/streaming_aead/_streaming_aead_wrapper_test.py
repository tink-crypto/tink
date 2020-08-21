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
from tink.proto import tink_pb2
from tink import core
from tink import streaming_aead
from tink.streaming_aead import _raw_streaming_aead
from tink.testing import bytes_io
from tink.testing import fake_streaming_aead
from tink.testing import helper


def setUpModule():
  streaming_aead.register()


def _primitive_key_pair(key_id):
  fake_key = helper.fake_key(key_id=key_id, output_prefix_type=tink_pb2.RAW)
  fake_saead = fake_streaming_aead.FakeRawStreamingAead(
      'fakeStreamingAead {}'.format(key_id))
  return fake_saead, fake_key


def _wrapped_saead(key_id):
  primitive, key = _primitive_key_pair(key_id)
  pset = core.new_primitive_set(_raw_streaming_aead.RawStreamingAead)
  entry = pset.add_primitive(primitive, key)
  pset.set_primary(entry)
  return core.Registry.wrap(pset, streaming_aead.StreamingAead)


def _readall(input_stream):
  output = bytearray()
  while True:
    d = input_stream.read()
    if d is None:
      continue
    output.extend(d)
    if not d:
      # d == b'', which means EOF
      return output


class StreamingAeadWrapperTest(parameterized.TestCase):

  @parameterized.parameters(
      [b'plaintext', b'', b'smile \xf0\x9f\x98\x80', b'\xf0\x9f\x98'])
  def test_encrypt_decrypt_success(self, plaintext):
    aad = b'associated_data'
    wrapped_saead = _wrapped_saead(1234)
    ciphertext_dest = bytes_io.BytesIOWithValueAfterClose()
    with wrapped_saead.new_encrypting_stream(ciphertext_dest, aad) as es:
      self.assertLen(plaintext, es.write(plaintext))
    self.assertTrue(ciphertext_dest.closed)

    ciphertext_src = io.BytesIO(ciphertext_dest.value_after_close())
    with wrapped_saead.new_decrypting_stream(ciphertext_src, aad) as ds:
      output = ds.read()
    self.assertTrue(ciphertext_src.closed)
    self.assertEqual(output, plaintext)

  def test_long_plaintext_encrypt_decrypt_success(self):
    long_plaintext = b' '.join(b'%d' % i for i in range(10 * 1000 * 1000))
    aad = b'associated_data'
    wrapped_saead = _wrapped_saead(1234)
    ciphertext_dest = bytes_io.BytesIOWithValueAfterClose()
    with wrapped_saead.new_encrypting_stream(ciphertext_dest, aad) as es:
      self.assertLen(long_plaintext, es.write(long_plaintext))
    self.assertTrue(ciphertext_dest.closed)

    ciphertext_src = io.BytesIO(ciphertext_dest.value_after_close())
    with wrapped_saead.new_decrypting_stream(ciphertext_src, aad) as ds:
      output = ds.read()
    self.assertTrue(ciphertext_src.closed)
    self.assertEqual(output, long_plaintext)

  def test_encrypt_decrypt_bad_aad(self):
    wrapped_saead = _wrapped_saead(1234)
    plaintext = b'plaintext'
    aad = b'associated_data'

    ciphertext_dest = bytes_io.BytesIOWithValueAfterClose()
    with wrapped_saead.new_encrypting_stream(ciphertext_dest, aad) as es:
      self.assertLen(plaintext, es.write(plaintext))
    self.assertTrue(ciphertext_dest.closed)

    ciphertext_src = io.BytesIO(ciphertext_dest.value_after_close())
    with wrapped_saead.new_decrypting_stream(ciphertext_src, b'bad aad') as ds:
      with self.assertRaises(core.TinkError):
        _ = ds.read()

  def test_decrypt_unknown_key_fails(self):
    plaintext = b'plaintext'
    aad = b'associated_data'

    unknown_saead = _wrapped_saead(1234)
    unknown_ciphertext_dest = bytes_io.BytesIOWithValueAfterClose()
    with unknown_saead.new_encrypting_stream(unknown_ciphertext_dest,
                                             aad) as es:
      es.write(plaintext)

    wrapped_saead = _wrapped_saead(2345)
    ciphertext_src = io.BytesIO(unknown_ciphertext_dest.value_after_close())
    with wrapped_saead.new_decrypting_stream(ciphertext_src, aad) as ds:
      with self.assertRaises(core.TinkError):
        _ = ds.read()

  @parameterized.parameters(
      [io.BytesIO, bytes_io.SlowBytesIO, bytes_io.SlowReadableRawBytes])
  def test_slow_encrypt_decrypt_with_two_keys(self, input_stream_factory):
    primitive1, key1 = _primitive_key_pair(1234)
    pset1 = core.new_primitive_set(_raw_streaming_aead.RawStreamingAead)
    entry1 = pset1.add_primitive(primitive1, key1)
    pset1.set_primary(entry1)
    old_primitive = core.Registry.wrap(pset1, streaming_aead.StreamingAead)

    plaintext1 = b' '.join(b'%d' % i for i in range(100 * 1000))
    aad1 = b'aad1'
    ciphertext_dest1 = bytes_io.BytesIOWithValueAfterClose()
    with old_primitive.new_encrypting_stream(ciphertext_dest1, aad1) as es:
      es.write(plaintext1)
    ciphertext1 = ciphertext_dest1.value_after_close()

    pset2 = core.new_primitive_set(_raw_streaming_aead.RawStreamingAead)
    pset2.add_primitive(primitive1, key1)
    primitive2, key2 = _primitive_key_pair(5678)
    entry2 = pset2.add_primitive(primitive2, key2)
    pset2.set_primary(entry2)
    new_primitive = core.Registry.wrap(pset2, streaming_aead.StreamingAead)

    plaintext2 = b' '.join(b'%d' % i for i in range(100 * 1001))
    aad2 = b'aad2'
    ciphertext_dest2 = bytes_io.BytesIOWithValueAfterClose()
    with new_primitive.new_encrypting_stream(ciphertext_dest2, aad2) as es:
      es.write(plaintext2)
    ciphertext2 = ciphertext_dest2.value_after_close()

    # old_primitive can read 1st ciphertext, but not the 2nd
    with old_primitive.new_decrypting_stream(
        cast(BinaryIO, input_stream_factory(ciphertext1)), aad1) as ds:
      self.assertEqual(_readall(ds), plaintext1)
    with old_primitive.new_decrypting_stream(
        cast(BinaryIO, input_stream_factory(ciphertext2)), aad2) as ds:
      with self.assertRaises(core.TinkError):
        _readall(ds)

    # new_primitive can read both ciphertexts
    with new_primitive.new_decrypting_stream(
        cast(BinaryIO, input_stream_factory(ciphertext1)), aad1) as ds:
      self.assertEqual(_readall(ds), plaintext1)
    with new_primitive.new_decrypting_stream(
        cast(BinaryIO, input_stream_factory(ciphertext2)), aad2) as ds:
      self.assertEqual(_readall(ds), plaintext2)


if __name__ == '__main__':
  absltest.main()
