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
"""Tests for tink.python.tink.streaming_aead.encrypting_stream."""

import io
from typing import cast

from absl.testing import absltest

from tink import core
from tink import streaming_aead
from tink.streaming_aead import _raw_streaming_aead

# Using malformed UTF-8 sequences to ensure there is no accidental decoding.
B_X80 = b'\x80'
B_AAD_ = b'aa' + B_X80
B_ASSOC_ = b'asso' + B_X80


def setUpModule():
  streaming_aead.register()


def get_raw_primitive():
  key_data = core.Registry.new_key_data(
      streaming_aead.streaming_aead_key_templates.AES128_CTR_HMAC_SHA256_4KB)
  return core.Registry.primitive(key_data, _raw_streaming_aead.RawStreamingAead)


class EncryptingStreamTest(absltest.TestCase):

  def test_write_non_bytes(self):
    f = io.BytesIO()
    with get_raw_primitive().new_raw_encrypting_stream(f, B_AAD_) as es:
      with self.assertRaisesRegex(TypeError, 'bytes-like object is required'):
        es.write(cast(bytes, 'This is a string, not a bytes object'))

  def test_flush(self):
    f = io.BytesIO()
    with get_raw_primitive().new_raw_encrypting_stream(f, B_ASSOC_) as es:
      es.write(b'Hello world!' + B_X80)
      es.flush()

  def test_closed(self):
    f = io.BytesIO()
    es = get_raw_primitive().new_raw_encrypting_stream(f, B_ASSOC_)
    es.write(b'Hello world!' + B_X80)
    es.close()

    self.assertTrue(es.closed)
    self.assertTrue(f.closed)

  def test_closed_methods_raise(self):
    f = io.BytesIO()
    es = get_raw_primitive().new_raw_encrypting_stream(f, B_ASSOC_)
    es.write(b'Hello world!' + B_X80)
    es.close()

    with self.assertRaisesRegex(ValueError, 'closed'):
      es.write(b'Goodbye world.' + B_X80)
    with self.assertRaisesRegex(ValueError, 'closed'):
      with es:
        pass
    with self.assertRaisesRegex(ValueError, 'closed'):
      es.flush()

  def test_unsupported_operation(self):
    f = io.BytesIO()
    with get_raw_primitive().new_raw_encrypting_stream(f, B_ASSOC_) as es:
      with self.assertRaises(io.UnsupportedOperation):
        es.seek(0, 2)
      with self.assertRaises(io.UnsupportedOperation):
        es.truncate(0)
      with self.assertRaises(io.UnsupportedOperation):
        es.read(-1)

  def test_inquiries(self):
    f = io.BytesIO()
    with get_raw_primitive().new_raw_encrypting_stream(f, B_ASSOC_) as es:
      self.assertTrue(es.writable())
      self.assertFalse(es.readable())
      self.assertFalse(es.seekable())

  def test_context_manager_exception_closes_dest_file(self):
    """Tests that exceptional exits trigger normal file closure.

    Any other behaviour seems to be difficult to implement, since standard
    file wrappers (such as io.BufferedWriter, or io.TextIOWrapper) will always
    close the wrapped file, even if an error was raised.
    """
    ciphertext_destination = io.BytesIO()
    with self.assertRaisesRegex(ValueError, 'raised inside'):
      with get_raw_primitive().new_raw_encrypting_stream(
          ciphertext_destination, B_ASSOC_) as es:
        es.write(b'some message' + B_X80)
        raise ValueError('Error raised inside context manager')
    self.assertTrue(ciphertext_destination.closed)


if __name__ == '__main__':
  absltest.main()
