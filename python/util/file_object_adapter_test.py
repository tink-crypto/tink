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
"""Tests for tink.python.util.file_object_adapter."""

from __future__ import absolute_import
from __future__ import division
from __future__ import print_function

import io

from absl.testing import absltest
from tink.python.util import file_object_adapter


class FileObjectAdapterTest(absltest.TestCase):

  def test_basic(self):
    file_object = io.BytesIO()
    adapter = file_object_adapter.FileObjectAdapter(file_object)
    self.assertEqual(9, adapter.write(b'something'))
    self.assertEqual(9, adapter.position())
    self.assertEqual(b'something', file_object.getvalue())
    adapter.close()

  def test_multiple_write(self):
    file_object = io.BytesIO()
    adapter = file_object_adapter.FileObjectAdapter(file_object)
    self.assertEqual(9, adapter.write(b'something'))
    self.assertEqual(3, adapter.write(b'123'))
    self.assertEqual(3, adapter.write(b'456'))
    self.assertEqual(b'something123456', file_object.getvalue())
    adapter.close()

  def test_write_after_close(self):
    file_object = io.BytesIO()
    adapter = file_object_adapter.FileObjectAdapter(file_object)
    adapter.close()
    self.assertRaises(ValueError, adapter.write, b'something')

  def test_position(self):
    file_object = io.BytesIO()
    adapter = file_object_adapter.FileObjectAdapter(file_object)
    self.assertEqual(0, adapter.position())
    self.assertEqual(9, adapter.write(b'something'))
    self.assertEqual(9, adapter.position())
    self.assertEqual(3, adapter.write(b'123'))
    self.assertEqual(12, adapter.position())
    adapter.close()

  def test_non_writable(self):

    class TestNonWritableObject(io.RawIOBase):
      """Test non-writable file-like object."""

      def writable(self):
        return False

    non_writable_object = TestNonWritableObject()
    self.assertRaises(TypeError, file_object_adapter.FileObjectAdapter,
                      non_writable_object)

  def test_partial_write(self):

    class TestFileObject(io.RawIOBase):
      """Test file-like object that always writes only first 5 bytes of data."""

      def __init__(self):
        super(TestFileObject, self).__init__()
        self.value = b''

      def writable(self):
        return True

      def write(self, data):
        self.value += data[:5]
        return 5

      def tell(self):
        return len(self.value)

    file_object = TestFileObject()
    adapter = file_object_adapter.FileObjectAdapter(file_object)
    self.assertEqual(5, adapter.write(b'something'))
    self.assertEqual(5, adapter.position())
    self.assertEqual(b'somet', file_object.value)


if __name__ == '__main__':
  absltest.main()
