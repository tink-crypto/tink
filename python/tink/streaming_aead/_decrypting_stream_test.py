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
"""Tests for tink.python.tink.streaming_aead.decrypting_stream."""

import io
from typing import BinaryIO

from absl.testing import absltest

from tink import core
from tink import streaming_aead
from tink.streaming_aead import _raw_streaming_aead

# Using malformed UTF-8 sequences to ensure there is no accidental decoding.
B_X80 = b'\x80'
B_SOMETHING_ = b'somethin' + B_X80
B_AAD_ = b'aa' + B_X80


def setUpModule():
  streaming_aead.register()


def get_raw_primitive():
  key_data = core.Registry.new_key_data(
      streaming_aead.streaming_aead_key_templates.AES128_CTR_HMAC_SHA256_4KB)
  return core.Registry.primitive(key_data, _raw_streaming_aead.RawStreamingAead)


def get_raw_decrypting_stream(
    ciphertext_source: BinaryIO,
    aad: bytes,
    close_ciphertext_source: bool = True) -> io.RawIOBase:
  return get_raw_primitive().new_raw_decrypting_stream(
      ciphertext_source, aad, close_ciphertext_source=close_ciphertext_source)


class DecryptingStreamTest(absltest.TestCase):

  def test_unsupported_operation(self):
    f = io.BytesIO(B_SOMETHING_)
    ds = get_raw_primitive().new_raw_decrypting_stream(
        f, B_AAD_, close_ciphertext_source=True)

    with self.assertRaises(io.UnsupportedOperation):
      ds.seek(0, 0)
    with self.assertRaises(io.UnsupportedOperation):
      ds.tell()
    with self.assertRaises(io.UnsupportedOperation):
      ds.truncate()
    with self.assertRaises(io.UnsupportedOperation):
      ds.write(b'data')
    with self.assertRaises(io.UnsupportedOperation):
      ds.writelines([b'data'])
    with self.assertRaises(io.UnsupportedOperation):
      ds.fileno()

  def test_closed_methods_raise(self):
    f = io.BytesIO(B_SOMETHING_)
    ds = get_raw_primitive().new_raw_decrypting_stream(
        f, B_AAD_, close_ciphertext_source=True)

    ds.close()
    with self.assertRaisesRegex(ValueError, 'closed'):
      ds.read()
    with self.assertRaisesRegex(ValueError, 'closed'):
      ds.flush()

  def test_inquiries(self):
    f = io.BytesIO(B_SOMETHING_)
    ds = get_raw_primitive().new_raw_decrypting_stream(
        f, B_AAD_, close_ciphertext_source=True)

    self.assertTrue(ds.readable())
    self.assertFalse(ds.writable())
    self.assertFalse(ds.seekable())
    self.assertFalse(ds.isatty())


if __name__ == '__main__':
  absltest.main()
