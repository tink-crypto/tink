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
"""Tests for tink.python.tink.testing.fake_streaming_aead."""

import io

from absl.testing import absltest
from tink import core
from tink.testing import bytes_io
from tink.testing import fake_streaming_aead


class FakeStreamingAeadTest(absltest.TestCase):

  def test_raw_fake_streaming_aead_success(self):
    saead = fake_streaming_aead.FakeRawStreamingAead('Name')

    ciphertext_dest = bytes_io.BytesIOWithValueAfterClose()
    with saead.new_raw_encrypting_stream(ciphertext_dest, b'aad') as es:
      self.assertLen(b'plaintext', es.write(b'plaintext'))
    self.assertTrue(ciphertext_dest.closed)

    for close_ciphertext_source in [False, True]:
      ciphertext_src = io.BytesIO(ciphertext_dest.value_after_close())
      with saead.new_raw_decrypting_stream(ciphertext_src, b'aad',
                                           close_ciphertext_source) as ds:
        output = ds.read()
      self.assertEqual(ciphertext_src.closed, close_ciphertext_source)
      self.assertEqual(output, b'plaintext')

  def test_raw_fake_streaming_aead_readall_success(self):
    saead = fake_streaming_aead.FakeRawStreamingAead('Name')

    ciphertext_dest = bytes_io.BytesIOWithValueAfterClose()
    with saead.new_raw_encrypting_stream(ciphertext_dest, b'aad') as es:
      self.assertLen(b'plaintext', es.write(b'plaintext'))
    self.assertTrue(ciphertext_dest.closed)

    ciphertext_src = io.BytesIO(ciphertext_dest.value_after_close())
    with saead.new_raw_decrypting_stream(
        ciphertext_src, b'aad', close_ciphertext_source=True) as ds:
      output = ds.readall()
    self.assertTrue(ciphertext_src.closed)
    self.assertEqual(output, b'plaintext')

  def test_fake_streaming_aead_slow_read_success(self):
    saead = fake_streaming_aead.FakeRawStreamingAead('Name')

    ciphertext_dest = bytes_io.BytesIOWithValueAfterClose()
    with saead.new_raw_encrypting_stream(ciphertext_dest, b'aad') as es:
      self.assertLen(b'plaintext', es.write(b'plaintext'))
    self.assertTrue(ciphertext_dest.closed)

    ciphertext_src = bytes_io.SlowReadableRawBytes(
        ciphertext_dest.value_after_close())
    with saead.new_raw_decrypting_stream(ciphertext_src, b'aad',
                                         close_ciphertext_source=True) as ds:
      # explicitly test that read returns None on the first call, because
      # that is needed to test one execution path in the wrapper.
      self.assertIsNone(ds.read())
      self.assertEqual(ds.read(), b'plaintext')

  def test_fake_streaming_aead_fails_wrong_key(self):
    saead1 = fake_streaming_aead.FakeRawStreamingAead('Name1')

    ciphertext_dest = bytes_io.BytesIOWithValueAfterClose()
    with saead1.new_raw_encrypting_stream(ciphertext_dest, b'aad') as es:
      self.assertLen(b'plaintext', es.write(b'plaintext'))
    self.assertTrue(ciphertext_dest.closed)

    saead2 = fake_streaming_aead.FakeRawStreamingAead('Name2')

    ciphertext_src = io.BytesIO(ciphertext_dest.value_after_close())
    with saead2.new_raw_decrypting_stream(
        ciphertext_src, b'aad', close_ciphertext_source=True) as ds:
      with self.assertRaises(core.TinkError):
        _ = ds.read()

  def test_fake_streaming_aead_fails_wrong_aad(self):
    saead = fake_streaming_aead.FakeRawStreamingAead('Name')

    ciphertext_dest = bytes_io.BytesIOWithValueAfterClose()
    with saead.new_raw_encrypting_stream(ciphertext_dest, b'aad') as es:
      self.assertLen(b'plaintext', es.write(b'plaintext'))
    self.assertTrue(ciphertext_dest.closed)

    ciphertext_src = io.BytesIO(ciphertext_dest.value_after_close())
    with saead.new_raw_decrypting_stream(
        ciphertext_src, b'bad aad', close_ciphertext_source=True) as ds:
      with self.assertRaises(core.TinkError):
        _ = ds.read()


if __name__ == '__main__':
  absltest.main()
