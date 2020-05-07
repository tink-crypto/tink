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
"""Wraps a AEAD CLI into a Python Tink Aead class."""

# Placeholder for import for type annotations

import os
import subprocess
import tempfile

import tink
from tink import cleartext_keyset_handle
from tink import mac

from typing import Text

# All languages that have an AEAD CLI.
LANGUAGES = ('cc', 'go', 'java', 'python')

# Path are relative to tools directory.
_MAC_CLI_PATHS = {
    'cc': 'testing/cc/mac_cli_cc',
    'go': 'testing/go/mac_cli_go',
    'java': 'testing/mac_cli_java',
    'python': 'testing/python/mac_cli_python',
}


def _tools_path() -> Text:
  util_path = os.path.dirname(os.path.abspath(__file__))
  return os.path.dirname(os.path.dirname(os.path.dirname(util_path)))


class CliMac(mac.Mac):
  """Wraps a Mac CLI binary into a Python primitive."""

  def __init__(self, lang: Text, keyset_handle: tink.KeysetHandle) -> None:
    self.lang = lang
    self._cli = os.path.join(_tools_path(), _MAC_CLI_PATHS[lang])
    self._keyset_handle = keyset_handle

  def compute_mac(self, data: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as tmpdir:
      keyset_filename = os.path.join(tmpdir, 'keyset_file')
      with open(keyset_filename, 'wb') as f:
        cleartext_keyset_handle.write(
            tink.BinaryKeysetWriter(f), self._keyset_handle)
      data_filename = os.path.join(tmpdir, 'data_file')
      with open(data_filename, 'wb') as f:
        f.write(data)
      mac_filename = os.path.join(tmpdir, 'mac_file')
      if os.path.exists(mac_filename):
        os.remove(mac_filename)
      try:
        unused_return_value = subprocess.check_output([
            self._cli, keyset_filename, 'compute', data_filename, mac_filename
        ])
      except subprocess.CalledProcessError as e:
        raise tink.TinkError(e)
      with open(mac_filename, 'rb') as f:
        mac_value = f.read()
      return mac_value

  def verify_mac(self, mac_value: bytes, data: bytes) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
      keyset_filename = os.path.join(tmpdir, 'keyset_file')
      with open(keyset_filename, 'wb') as f:
        cleartext_keyset_handle.write(
            tink.BinaryKeysetWriter(f), self._keyset_handle)
      data_filename = os.path.join(tmpdir, 'data_file')
      with open(data_filename, 'wb') as f:
        f.write(data)
      mac_filename = os.path.join(tmpdir, 'mac_file')
      with open(mac_filename, 'wb') as f:
        f.write(mac_value)
      result_filename = os.path.join(tmpdir, 'result_file')
      if os.path.exists(result_filename):
        os.remove(result_filename)
      try:
        unused_return_value = subprocess.check_output([
            self._cli, keyset_filename, 'verify',
            data_filename, mac_filename, result_filename
        ])
      except subprocess.CalledProcessError as e:
        raise tink.TinkError(e)
      with open(result_filename, 'rb') as f:
        result = f.read()
      if result != b'valid':
        raise tink.TinkError('verification failed')
      return None
