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
import mock
from tink.python.util import file_object_adapter


class FileObjectAdapterTest(absltest.TestCase):

  def test_basic(self):
    file_object = io.BytesIO()
    adapter = file_object_adapter.FileObjectAdapter(file_object)
    self.assertEqual(9, adapter.write(b'something'))
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

  def test_non_writable(self):
    file_object = mock.Mock()
    file_object.writable = mock.Mock(return_value=False)

    self.assertRaises(TypeError, file_object_adapter.FileObjectAdapter,
                      file_object)

  def test_write_returns_none(self):
    file_object = mock.Mock()
    file_object.writable = mock.Mock(return_value=True)
    file_object.write = mock.Mock(return_value=None)

    adapter = file_object_adapter.FileObjectAdapter(file_object)
    self.assertEqual(0, adapter.write(b'something'))

  def test_write_raises_blocking_error(self):
    file_object = mock.Mock()
    file_object.writable = mock.Mock(return_value=True)
    file_object.write = mock.Mock(side_effect=io.BlockingIOError(None, None, 5))

    adapter = file_object_adapter.FileObjectAdapter(file_object)
    self.assertEqual(5, adapter.write(b'something'))

  def test_partial_write(self):
    file_object = mock.Mock()
    file_object.writable = mock.Mock(return_value=True)
    file_object.write = mock.Mock(wraps=lambda data: len(data) - 1)

    adapter = file_object_adapter.FileObjectAdapter(file_object)
    self.assertEqual(8, adapter.write(b'something'))


if __name__ == '__main__':
  absltest.main()
