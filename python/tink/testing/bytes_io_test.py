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
"""Tests for tink.python.tink.util.bytes_io."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import io

from absl.testing import absltest
from tink.testing import bytes_io


class BytesIoTest(absltest.TestCase):

  def test_close_success(self):
    f = bytes_io.BytesIOWithValueAfterClose()
    f.write(b'foobar')
    f.close()
    self.assertEqual(f.value_after_close(), b'foobar')

  def test_with_text_wrapper_success(self):
    f = bytes_io.BytesIOWithValueAfterClose()
    with io.TextIOWrapper(f, encoding='utf8') as t:
      t.write(u'foobar')
    self.assertTrue(f.closed)
    value = f.value_after_close()
    self.assertEqual(value, u'foobar'.encode('utf8'))

  def test_initial_bytes_success(self):
    f = bytes_io.BytesIOWithValueAfterClose(b'abc')
    f.write(b'foobar')
    f.close()
    self.assertEqual(f.value_after_close(), b'foobar')

  def test_value_before_close_fails(self):
    f = bytes_io.BytesIOWithValueAfterClose()
    f.write(b'foobar')
    with self.assertRaises(ValueError):
      f.value_after_close()
    f.close()

  def test_close_twice_success(self):
    f = bytes_io.BytesIOWithValueAfterClose(b'abc')
    f.write(b'foobar')
    f.close()
    f.close()
    self.assertEqual(f.value_after_close(), b'foobar')


class SlowBytesIOTest(absltest.TestCase):

  def test_read(self):
    with bytes_io.SlowBytesIO(b'The quick brown fox') as f:
      with self.assertRaises(io.BlockingIOError):
        f.read(10)
      self.assertEqual(b'The q', f.read(10))
      self.assertEqual(b'uick ', f.read(10))
      with self.assertRaises(io.BlockingIOError):
        f.read(10)
      self.assertEqual(b'brown', f.read(10))
      self.assertEqual(b' fox', f.read(10))
      with self.assertRaises(io.BlockingIOError):
        f.read(10)
      self.assertEqual(b'', f.read(10))
    self.assertTrue(f.closed)

  def test_read_no_argument(self):
    with bytes_io.SlowBytesIO(b'The quick brown fox') as f:
      self.assertEqual(b'The quick brown fox', f.read())
      self.assertEqual(b'', f.read())

  def test_read_minus_one(self):
    with bytes_io.SlowBytesIO(b'The quick brown fox') as f:
      self.assertEqual(b'The quick brown fox', f.read(-1))
      self.assertEqual(b'', f.read(-1))

  def test_not_seekable(self):
    with bytes_io.SlowBytesIO(b'The quick brown fox', seekable=False) as f:
      self.assertFalse(f.seekable())
      with self.assertRaises(io.UnsupportedOperation):
        f.seek(0)

  def test_seekable(self):
    with bytes_io.SlowBytesIO(b'The quick brown fox', seekable=True) as f:
      self.assertTrue(f.seekable())
      self.assertEqual(b'The quick brown fox', f.read())
      f.seek(0)
      self.assertEqual(b'The quick brown fox', f.read())


class SlowReadableRawBytesTest(absltest.TestCase):

  def test_read(self):
    with bytes_io.SlowReadableRawBytes(b'The quick brown fox') as f:
      self.assertIsNone(f.read(10))
      self.assertEqual(b'The q', f.read(10))
      self.assertEqual(b'uick ', f.read(10))
      self.assertIsNone(f.read(10))
      self.assertEqual(b'brown', f.read(10))
      self.assertEqual(b' fox', f.read(10))
      self.assertIsNone(f.read(10))
      self.assertEqual(b'', f.read(10))
    self.assertTrue(f.closed)

  # Note that the documentation of readall(), read() and read(-1) is wrong:
  # https://docs.python.org/2/library/io.html#io.RawIOBase.readall.
  # readall does multiple reads, but it stops as soon as it can't read any data.
  # The documentation says that it reads until it reaches EOF.
  def test_readall(self):
    with bytes_io.SlowReadableRawBytes(b'The quick brown fox') as f:
      self.assertIsNone(None, f.readall())
      self.assertEqual(b'The quick ', f.readall())
      self.assertEqual(b'brown fox', f.readall())
      self.assertEqual(b'', f.readall())

  def test_read_no_argument(self):
    with bytes_io.SlowReadableRawBytes(b'The quick brown fox') as f:
      self.assertIsNone(None, f.read())
      self.assertEqual(b'The quick ', f.read())
      self.assertEqual(b'brown fox', f.read())
      self.assertEqual(b'', f.read())

  def test_read_minus_one(self):
    with bytes_io.SlowReadableRawBytes(b'The quick brown fox') as f:
      self.assertIsNone(None, f.read(-1))
      self.assertEqual(b'The quick ', f.read(-1))
      self.assertEqual(b'brown fox', f.read(-1))
      self.assertEqual(b'', f.read(-1))

  def test_not_seekable(self):
    with bytes_io.SlowReadableRawBytes(
        b'The quick brown fox', seekable=False) as f:
      self.assertFalse(f.seekable())
      with self.assertRaises(io.UnsupportedOperation):
        f.seek(0)

  def test_seekable(self):
    with bytes_io.SlowReadableRawBytes(
        b'The quick brown fox', seekable=True) as f:
      self.assertTrue(f.seekable())
      self.assertIsNone(None, f.read())
      self.assertEqual(b'The quick ', f.read())
      f.seek(0)
      self.assertEqual(b'The quick ', f.read())

if __name__ == '__main__':
  absltest.main()
