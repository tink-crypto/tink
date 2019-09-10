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
"""FileObjectAdapter class.

Used in conjunction with PythonOutputStream to allow a C++ OutputStream
to write to a Python file-like object.
"""

from __future__ import absolute_import
from __future__ import division
from __future__ import google_type_annotations
from __future__ import print_function

import io
from typing import BinaryIO

from tink.python.cc.clif import python_file_object_adapter


class FileObjectAdapter(python_file_object_adapter.PythonFileObjectAdapter):
  """Adapts a Python file object for use in C++."""

  def __init__(self, file_object: BinaryIO):
    if not file_object.writable():
      raise TypeError('File object must be writable.')
    self._file_object = file_object

  def write(self, data: bytes) -> int:
    """Writes to underlying file object and returns number of bytes written."""
    try:
      written = self._file_object.write(data)
      return 0 if written is None else written
    except io.BlockingIOError as e:
      return e.characters_written

  def close(self) -> None:
    self._file_object.close()
