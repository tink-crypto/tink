# Lint as: python3
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

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import io
import sys
from typing import cast, BinaryIO

from absl.testing import absltest
from absl.testing.absltest import mock

from tink import streaming_aead
from tink.testing import bytes_io

# Using malformed UTF-8 sequences to ensure there is no accidental decoding.
B_X80 = b'\x80'
B_AAD_ = b'aa' + B_X80
B_ASSOC_ = b'asso' + B_X80


class FakeOutputStreamAdapter(object):

  def __init__(self, destination):
    self._destination = destination

  def write(self, data):
    return self._destination.write(data)

  def close(self):
    self._destination.close()


def fake_get_output_stream_adapter(self, cc_primitive, aad, destination):
  del cc_primitive, aad, self  # unused
  return FakeOutputStreamAdapter(destination)


# We use the same return type as StreamingAead.new_decrypting_stream
def get_encrypting_stream(ciphertext_destination: BinaryIO,
                          aad: bytes) -> BinaryIO:
  s = streaming_aead.EncryptingStream(None, ciphertext_destination, aad)
  return cast(BinaryIO, s)


class EncryptingStreamTest(absltest.TestCase):

  def setUp(self):
    super(EncryptingStreamTest, self).setUp()
    # Replace the EncryptingStream's staticmethod with a custom function to
    # avoid the need for a Streaming AEAD primitive.
    self.addCleanup(mock.patch.stopall)
    mock.patch.object(
        streaming_aead.EncryptingStream,
        '_get_output_stream_adapter',
        new=fake_get_output_stream_adapter).start()

  def test_non_writable_object(self):
    f = mock.Mock()
    f.writable = mock.Mock(return_value=False)
    with self.assertRaisesRegex(ValueError, 'writable'):
      get_encrypting_stream(f, B_AAD_)

  def test_write(self):
    f = bytes_io.BytesIOWithValueAfterClose()
    with get_encrypting_stream(f, B_AAD_) as es:
      es.write(b'Hello world!' + B_X80)
    self.assertTrue(f.closed)
    self.assertEqual(b'Hello world!' + B_X80, f.value_after_close())

  @absltest.skipIf(sys.version_info[0] == 2, 'Python 2 strings are bytes')
  def test_write_non_bytes(self):
    with io.BytesIO() as f, get_encrypting_stream(f, B_AAD_) as es:
      with self.assertRaisesRegex(TypeError, 'bytes-like object is required'):
        es.write(cast(bytes, 'This is a string, not a bytes object'))

  def test_textiowrapper_compatibility(self):
    """A test that checks the TextIOWrapper works as expected.

    It encrypts the same plaintext twice - once directly from bytes, and once
    through TextIOWrapper's encoding. The two ciphertexts should have the same
    length.
    """
    file_1 = bytes_io.BytesIOWithValueAfterClose()
    file_2 = bytes_io.BytesIOWithValueAfterClose()

    with get_encrypting_stream(file_1, B_AAD_) as es:
      with io.TextIOWrapper(es) as wrapper:
        wrapper.write(b'some data'.decode('utf-8'))

    with get_encrypting_stream(file_2, B_AAD_) as es:
      es.write(b'some data')

    self.assertEqual(len(file_1.value_after_close()),
                     len(file_2.value_after_close()))

  def test_flush(self):
    with io.BytesIO() as f, get_encrypting_stream(f, B_ASSOC_) as es:
      es.write(b'Hello world!' + B_X80)
      es.flush()

  def test_closed(self):
    f = io.BytesIO()
    es = get_encrypting_stream(f, B_ASSOC_)
    es.write(b'Hello world!' + B_X80)
    es.close()

    self.assertTrue(es.closed)
    self.assertTrue(f.closed)

  def test_closed_methods_raise(self):
    f = io.BytesIO()
    es = get_encrypting_stream(f, B_ASSOC_)
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
    with io.BytesIO() as f, get_encrypting_stream(f, B_ASSOC_) as es:
      with self.assertRaisesRegex(io.UnsupportedOperation, 'seek'):
        es.seek(0, 2)
      with self.assertRaisesRegex(io.UnsupportedOperation, 'truncate'):
        es.truncate(0)
      with self.assertRaisesRegex(io.UnsupportedOperation, 'read'):
        es.read(-1)

  def test_inquiries(self):
    with io.BytesIO() as f, get_encrypting_stream(f, B_ASSOC_) as es:
      self.assertTrue(es.writable())
      self.assertFalse(es.readable())
      self.assertFalse(es.seekable())

  def test_position(self):
    with io.BytesIO() as f:
      # Cast is needed since read1 is not part of BinaryIO.
      with cast(streaming_aead.EncryptingStream,
                get_encrypting_stream(f, B_ASSOC_)) as es:
        es.write(b'Hello world' + B_X80)
        self.assertEqual(es.position(), 12)

  def test_position_works_closed(self):
    with io.BytesIO() as f:
      # Cast is needed since position is not part of BinaryIO.
      es = cast(streaming_aead.EncryptingStream,
                get_encrypting_stream(f, B_ASSOC_))

      es.write(b'Hello world' + B_X80)
      es.close()

      self.assertTrue(es.closed)
      self.assertEqual(es.position(), 12)

  def test_blocking_io(self):

    class OnlyWritesFirstFiveBytes(io.BytesIO):

      def write(self, buffer):
        buffer = buffer[:5]
        n = super(OnlyWritesFirstFiveBytes, self).write(buffer)
        return n

    with OnlyWritesFirstFiveBytes() as f:
      with get_encrypting_stream(f, B_ASSOC_) as es:
        with self.assertRaisesRegex(io.BlockingIOError, 'could not complete'):
          es.write(b'Hello world!' + B_X80)

  def test_context_manager_exception_close(self):
    """Tests that exceptional exits do not trigger normal file closure.

    Instead, the file will be closed without a proper final ciphertext block,
    and will result in an invalid ciphertext. The ciphertext_destination file
    object itself should in most cases still be closed when garbage collected.
    """
    ciphertext_destination = io.BytesIO()
    with self.assertRaisesRegex(ValueError, 'raised inside'):
      with get_encrypting_stream(ciphertext_destination, B_ASSOC_) as es:
        es.write(b'some message' + B_X80)
        raise ValueError('Error raised inside context manager')

    self.assertFalse(ciphertext_destination.closed)


if __name__ == '__main__':
  absltest.main()
