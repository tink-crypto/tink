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

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import io

from absl.testing import absltest
from absl.testing.absltest import mock

from tink import core
from tink import streaming_aead
from tink.cc.pybind import tink_bindings

# Using malformed UTF-8 sequences to ensure there is no accidental decoding.
B_X80 = b'\x80'
B_SOMETHING_ = b'somethin' + B_X80
B_AAD_ = b'aa' + B_X80


class FakeInputStreamAdapter(object):

  def __init__(self, file_object_adapter):
    self._adapter = file_object_adapter

  @core.use_tink_errors
  def read(self, size=-1):
    try:
      if size < 0:
        size = 100
      return self._adapter.read(size)
    except EOFError:
      raise tink_bindings.StatusNotOk(11, 'EOF')

  def read1(self, size=-1):
    del size  # unused
    return self.read(4)


def fake_get_input_stream_adapter(self, cc_primitive, aad, source):
  del cc_primitive, aad, self  # unused
  return FakeInputStreamAdapter(source)


def get_decrypting_stream(ciphertext_source, aad):
  return streaming_aead.DecryptingStream(None, ciphertext_source, aad)


class DecryptingStreamTest(absltest.TestCase):

  def setUp(self):
    super(DecryptingStreamTest, self).setUp()
    # Replace the DecryptingStream's staticmethod with a custom function to
    # avoid the need for a Streaming AEAD primitive.
    self.addCleanup(mock.patch.stopall)
    mock.patch.object(
        streaming_aead.DecryptingStream,
        '_get_input_stream_adapter',
        new=fake_get_input_stream_adapter).start()

  def test_non_readable_object(self):
    f = mock.Mock()
    f.readable = mock.Mock(return_value=False)

    with self.assertRaisesRegex(ValueError, 'readable'):
      get_decrypting_stream(f, B_AAD_)

  def test_read(self):
    f = io.BytesIO(B_SOMETHING_)
    ds = get_decrypting_stream(f, B_AAD_)

    self.assertEqual(ds.read(9), B_SOMETHING_)

  def test_read1(self):
    f = io.BytesIO(B_SOMETHING_)
    ds = get_decrypting_stream(f, B_AAD_)

    self.assertEqual(ds.read1(9), b'some')

  def test_readinto(self):
    f = io.BytesIO(B_SOMETHING_)
    ds = get_decrypting_stream(f, B_AAD_)

    b = bytearray(9)
    self.assertEqual(ds.readinto(b), 9)
    self.assertEqual(bytes(b), B_SOMETHING_)

  def test_readinto1(self):
    f = io.BytesIO(B_SOMETHING_)
    ds = get_decrypting_stream(f, B_AAD_)

    b = bytearray(9)
    self.assertEqual(ds.readinto1(b), 4)
    self.assertEqual(bytes(b[:4]), b'some')

  def test_read_until_eof(self):
    f = io.BytesIO(B_SOMETHING_)
    ds = get_decrypting_stream(f, B_AAD_)

    self.assertEqual(ds.read(), B_SOMETHING_)

  def test_read_eof_reached(self):
    f = io.BytesIO()
    ds = get_decrypting_stream(f, B_AAD_)

    self.assertEqual(ds.read(), b'')

  def test_read_no_data_available(self):
    f = mock.Mock()
    f.read = mock.Mock(return_value=None)
    f.readable = mock.Mock(return_value=True)
    ds = get_decrypting_stream(f, B_AAD_)

    with self.assertRaises(io.BlockingIOError):
      ds.read(5)

  def test_unsupported_operation(self):
    f = io.BytesIO(B_SOMETHING_)
    ds = get_decrypting_stream(f, B_AAD_)

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
    with self.assertRaises(io.UnsupportedOperation):
      ds.detach()

  def test_closed(self):
    f = io.BytesIO(B_SOMETHING_)
    ds = get_decrypting_stream(f, B_AAD_)

    self.assertFalse(ds.closed)
    self.assertFalse(f.closed)
    ds.close()
    self.assertTrue(ds.closed)
    self.assertTrue(f.closed)
    ds.close()

  def test_closed_methods_raise(self):
    f = io.BytesIO(B_SOMETHING_)
    ds = get_decrypting_stream(f, B_AAD_)

    ds.close()
    with self.assertRaisesRegex(ValueError, 'closed'):
      ds.read()
    with self.assertRaisesRegex(ValueError, 'closed'):
      ds.flush()
    with self.assertRaisesRegex(ValueError, 'closed'):
      ds.__enter__()
    with self.assertRaisesRegex(ValueError, 'closed'):
      ds.__iter__()
    with self.assertRaisesRegex(ValueError, 'closed'):
      ds.isatty()

  def test_position(self):
    f = io.BytesIO(B_SOMETHING_)
    ds = get_decrypting_stream(f, B_AAD_)

    self.assertEqual(ds.position(), 0)
    ds.read(4)
    self.assertEqual(ds.position(), 4)
    ds.read(4)
    self.assertEqual(ds.position(), 8)
    ds.close()
    self.assertEqual(ds.position(), 8)

  def test_inquiries(self):
    f = io.BytesIO(B_SOMETHING_)
    ds = get_decrypting_stream(f, B_AAD_)

    self.assertTrue(ds.readable())
    self.assertFalse(ds.writable())
    self.assertFalse(ds.seekable())
    self.assertFalse(ds.isatty())

  def test_context_manager(self):
    f = io.BytesIO(B_SOMETHING_)

    with get_decrypting_stream(f, B_AAD_) as ds:
      self.assertEqual(ds.read(), B_SOMETHING_)
    self.assertTrue(ds.closed)

  def test_readline(self):
    f = io.BytesIO(b'hello\nworld\n')
    ds = get_decrypting_stream(f, B_AAD_)

    self.assertEqual(ds.readline(), b'hello\n')
    self.assertEqual(ds.readline(), b'world\n')

  def test_readline_with_size(self):
    f = io.BytesIO(b'hello\nworld\n')
    ds = get_decrypting_stream(f, B_AAD_)

    self.assertEqual(ds.readline(4), b'hell')
    self.assertEqual(ds.readline(4), b'o\n')

  def test_readlines(self):
    f = io.BytesIO(b'hello\nworld\n')
    ds = get_decrypting_stream(f, B_AAD_)

    self.assertEqual(ds.readlines(), [b'hello\n', b'world\n'])

  def test_readlines_with_hint(self):
    f = io.BytesIO(b'hello\nworld\n!!!\n')
    ds = get_decrypting_stream(f, B_AAD_)

    self.assertEqual(ds.readlines(10), [b'hello\n', b'world\n'])

  def test_iterator(self):
    f = io.BytesIO(b'hello\nworld\n')

    result = []
    for line in get_decrypting_stream(f, B_AAD_):
      result.append(line)

    self.assertEqual(result, [b'hello\n', b'world\n'])

  def test_textiowrapper_compatibility(self):
    """A test that checks the TextIOWrapper works as expected.

    It decrypts the same ciphertext twice - once directly from bytes, and once
    through TextIOWrapper's encoding. The two plaintexts should have the same
    length.
    """
    file_1 = io.BytesIO(b'something')
    file_2 = io.BytesIO(b'something')

    with get_decrypting_stream(file_1, B_AAD_) as ds:
      with io.TextIOWrapper(ds) as wrapper:
        data_1 = wrapper.read()

    with get_decrypting_stream(file_2, B_AAD_) as ds:
      data_2 = ds.read()

    self.assertEqual(len(data_1), len(data_2))


if __name__ == '__main__':
  absltest.main()
