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
"""Wraps a Deterministic AEAD CLI into a Python Tink DeterministicAead class."""

# Placeholder for import for type annotations

import os
import subprocess
import tempfile

from typing import Text

import tink
from tink import cleartext_keyset_handle
from tink import daead


# All languages that have an Deterministic AEAD CLI.
LANGUAGES = ('cc', 'go', 'java', 'python')

# Path are relative to tools directory.
_DAEAD_CLI_PATHS = {
    'cc': 'testing/cc/deterministic_aead_cli_cc',
    'go': 'testing/go/deterministic_aead_cli_go',
    'java': 'testing/deterministic_aead_cli_java',
    'python': 'testing/python/deterministic_aead_cli_python',
}


def _tools_path() -> Text:
  util_path = os.path.dirname(os.path.abspath(__file__))
  return os.path.dirname(os.path.dirname(os.path.dirname(util_path)))


class CliDeterministicAead(daead.DeterministicAead):
  """Wraps Deterministic AEAD CLI binary into a DeterministicAead primitive."""

  def __init__(self, lang: Text, keyset_handle: tink.KeysetHandle) -> None:
    self.lang = lang
    self._cli = os.path.join(_tools_path(), _DAEAD_CLI_PATHS[lang])
    self._keyset_handle = keyset_handle

  def _run(self, operation: Text, input_data: bytes,
           associated_data: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as tmpdir:
      keyset_filename = os.path.join(tmpdir, 'keyset_file')
      input_filename = os.path.join(tmpdir, 'input_file')
      associated_data_filename = os.path.join(tmpdir, 'associated_data_file')
      output_filename = os.path.join(tmpdir, 'output_file')
      with open(keyset_filename, 'wb') as f:
        cleartext_keyset_handle.write(
            tink.BinaryKeysetWriter(f), self._keyset_handle)
      with open(input_filename, 'wb') as f:
        f.write(input_data)
      with open(associated_data_filename, 'wb') as f:
        f.write(associated_data)
      try:
        unused_return_value = subprocess.check_output([
            self._cli, keyset_filename, operation,
            input_filename, associated_data_filename, output_filename
        ])
      except subprocess.CalledProcessError as e:
        raise tink.TinkError(e)
      with open(output_filename, 'rb') as f:
        output_data = f.read()
      return output_data

  def encrypt_deterministically(
      self, plaintext: bytes, associated_data: bytes) -> bytes:
    return self._run('encryptdeterministically', plaintext, associated_data)

  def decrypt_deterministically(
      self, ciphertext: bytes, associated_data: bytes) -> bytes:
    return self._run('decryptdeterministically', ciphertext, associated_data)

