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
from __future__ import print_function

import io
import tempfile
from typing import BinaryIO, cast
from absl.testing import absltest
from absl.testing import parameterized

from tink.streaming_aead import _rewindable_input_stream
from tink.testing import bytes_io


class NonSeekableBytesIO(io.BytesIO):

  def seekable(self) -> bool:
    return False


def _rewindable(data,
                seekable) -> _rewindable_input_stream.RewindableInputStream:
  if seekable:
    b = cast(BinaryIO, io.BytesIO(data))
  else:
    b = cast(BinaryIO, NonSeekableBytesIO(data))
  return _rewindable_input_stream.RewindableInputStream(b)


class RewindableInputStreamTest(parameterized.TestCase):

  @parameterized.parameters([False, True])
  def test_read(self, seekable):
    with _rewindable(b'The quick brown fox', seekable) as f:
      self.assertEqual(b'The q', f.read(5))
      self.assertEqual(b'uick ', f.read(5))
      self.assertEqual(b'brown', f.read(5))
      self.assertEqual(b' fox', f.read(5))
      self.assertEqual(b'', f.read(5))
      self.assertEqual(b'', f.read(5))

  @parameterized.parameters([False, True])
  def test_read_no_argument(self, seekable):
    with _rewindable(b'The quick brown fox', seekable) as f:
      self.assertEqual(b'The quick brown fox', f.read())

  @parameterized.parameters([False, True])
  def test_read_minus_one(self, seekable):
    with _rewindable(b'The quick brown fox', seekable) as f:
      self.assertEqual(b'The quick brown fox', f.read(-1))

  @parameterized.parameters([False, True])
  def test_readall(self, seekable):
    with _rewindable(b'The quick brown fox', seekable) as f:
      self.assertEqual(b'The quick brown fox', f.readall())

  @parameterized.parameters([False, True])
  def test_rewind_read(self, seekable):
    with _rewindable(b'The quick brown fox', seekable) as f:
      self.assertEqual(b'The quick', f.read(9))
      f.rewind()
      self.assertEqual(b'The ', f.read(4))
      # this only reads the rest of current buffer content.
      self.assertEqual(b'quick', f.read(100))
      self.assertEqual(b' brown fox', f.read())

  @parameterized.parameters([False, True])
  def test_rewind_readall(self, seekable):
    with _rewindable(b'The quick brown fox', seekable) as f:
      self.assertEqual(b'The q', f.read(5))
      f.rewind()
      # this must read the whole file.
      self.assertEqual(b'The quick brown fox', f.read())

  @parameterized.parameters([False, True])
  def test_rewind_twice(self, seekable):
    with _rewindable(b'The quick brown fox', seekable) as f:
      self.assertEqual(b'The q', f.read(5))
      f.rewind()
      self.assertEqual(b'The q', f.read(5))
      self.assertEqual(b'uick ', f.read(5))
      f.rewind()
      self.assertEqual(b'The quick brown fox', f.read())

  @parameterized.parameters([False, True])
  def test_disable_rewind(self, seekable):
    with _rewindable(b'The quick brown fox', seekable) as f:
      self.assertEqual(b'The q', f.read(5))
      f.rewind()
      f.disable_rewind()
      # this only reads the current buffer content.
      self.assertEqual(b'The q', f.read(100))
      self.assertEqual(b'u', f.read(1))
      self.assertEmpty(f._buffer)
      self.assertEqual(b'ick brown fox', f.read())

  @parameterized.parameters([False, True])
  def test_disable_rewind_readall(self, seekable):
    with _rewindable(b'The quick brown fox', seekable) as f:
      self.assertEqual(b'The q', f.read(5))
      f.rewind()
      f.disable_rewind()
      self.assertEqual(b'The quick brown fox', f.read())

  def test_nonreadable_input_fail(self):
    with tempfile.TemporaryFile('wb') as f:
      with self.assertRaises(ValueError):
        _ = _rewindable_input_stream.RewindableInputStream(cast(BinaryIO, f))


class RewindableInputStreamSlowTest(parameterized.TestCase):
  """Tests "slow" input streams where read returns None or BlockingIOError.

  Normally, this should not happen in blocking streams.
  """

  @parameterized.parameters([False, True])
  def test_read_slow(self, seekable):
    input_stream = bytes_io.SlowBytesIO(b'The quick brown fox', seekable)
    with _rewindable_input_stream.RewindableInputStream(
        cast(BinaryIO, input_stream)) as f:
      self.assertIsNone(f.read(10))
      self.assertEqual(b'The q', f.read(10))
      self.assertEqual(b'uick ', f.read(10))
      self.assertIsNone(f.read(10))
      self.assertEqual(b'brown', f.read(10))
      self.assertEqual(b' fox', f.read(10))
      self.assertIsNone(f.read(10))
      self.assertEqual(b'', f.read(10))

  @parameterized.parameters([False, True])
  def test_read_slow_raw(self, seekable):
    input_stream = bytes_io.SlowReadableRawBytes(b'The quick brown fox',
                                                 seekable)
    with _rewindable_input_stream.RewindableInputStream(
        cast(BinaryIO, input_stream)) as f:
      self.assertIsNone(f.read(10))
      self.assertEqual(b'The q', f.read(10))
      self.assertEqual(b'uick ', f.read(10))
      self.assertIsNone(f.read(10))
      self.assertEqual(b'brown', f.read(10))
      self.assertEqual(b' fox', f.read(10))
      self.assertIsNone(f.read(10))
      self.assertEqual(b'', f.read(10))

  @parameterized.parameters([False, True])
  def test_read_slow_raw_readall(self, seekable):
    input_stream = bytes_io.SlowReadableRawBytes(b'The quick brown fox',
                                                 seekable)
    with _rewindable_input_stream.RewindableInputStream(
        cast(BinaryIO, input_stream)) as f:
      self.assertIsNone(f.readall())
      self.assertEqual(b'The quick ', f.readall())
      self.assertEqual(b'brown fox', f.readall())
      self.assertEqual(b'', f.readall())


if __name__ == '__main__':
  absltest.main()
