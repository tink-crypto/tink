# Copyright 2022 Google LLC
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

"""Tests for tink.tink.testing.cross_language.util.path_util."""

import os

from absl.testing import absltest
from util import _path_util


class PathUtilTest(absltest.TestCase):

  def test_tink_root_path(self):
    path = os.path.join(_path_util.tink_root_path(), 'LICENSE')
    with open(path, mode='rt') as f:
      tink_license = f.read()
    self.assertNotEmpty(tink_license)

if __name__ == '__main__':
  absltest.main()
