# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License")
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
"""Utility functions for file paths."""

import os

_GOOGLE3_TINK_BASE_PATH = 'google3/third_party/tink'


def tink_root_path() -> str:
  """Returns the path to the Tink root directory used for the test enviroment.

     The path can be set in the TINK_SRC_PATH enviroment variable. If Bazel
     is used the path is derived from the Bazel enviroment variables. If that
     does not work, it generates the root path relative to the __file__ path.
  """
  root_paths = []
  if 'TINK_SRC_PATH' in os.environ:
    root_paths.append(os.environ['TINK_SRC_PATH'])
  if 'TEST_SRCDIR' in os.environ:
    # Bazel enviroment
    root_paths.append(os.path.join(os.environ['TEST_SRCDIR'], 'tink_base'))
    root_paths.append(
        os.path.join(os.environ['TEST_SRCDIR'], _GOOGLE3_TINK_BASE_PATH))
  for root_path in root_paths:
    # return the first path that exists.
    if os.path.exists(root_path):
      return root_path
  raise ValueError(
      'Could not find path to Tink root directory among the available paths: '
      f'{root_paths}. If a custom Tink root path is provided via TINK_SRC_PATH,'
      ' make sure it is correct.')
