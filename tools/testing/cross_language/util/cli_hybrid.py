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
"""Wraps Hybrid Encryption CLIs into a Python Tink classes."""

# Placeholder for import for type annotations

import os
import subprocess
import tempfile

from typing import Text

import tink
from tink import cleartext_keyset_handle
from tink import hybrid


# All languages that have a Hybrid Encryption CLI.
LANGUAGES = ('cc', 'go', 'java', 'python')

# Path are relative to tools directory.
_ENCRYPT_CLI_PATHS = {
    'cc': 'testing/cc/hybrid_encrypt_cli_cc',
    'go': 'testing/go/hybrid_encrypt_cli_go',
    'java': 'testing/hybrid_encrypt_cli_java',
    'python': 'testing/python/hybrid_encrypt_cli_python',
}

_DECRYPT_CLI_PATHS = {
    'cc': 'testing/cc/hybrid_decrypt_cli_cc',
    'go': 'testing/go/hybrid_decrypt_cli_go',
    'java': 'testing/hybrid_decrypt_cli_java',
    'python': 'testing/python/hybrid_decrypt_cli_python',
}


def _tools_path() -> Text:
  util_path = os.path.dirname(os.path.abspath(__file__))
  return os.path.dirname(os.path.dirname(os.path.dirname(util_path)))


class CliHybridEncrypt(hybrid.HybridEncrypt):
  """Wraps a HybridEncrypt CLI binary into a Python primitive."""

  def __init__(self, lang: Text,
               public_keyset_handle: tink.KeysetHandle) -> None:
    self.lang = lang
    self._cli = os.path.join(_tools_path(), _ENCRYPT_CLI_PATHS[lang])
    self._public_keyset_handle = public_keyset_handle

  def encrypt(self, plaintext: bytes, context_info: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as tmpdir:
      public_keyset_filename = os.path.join(tmpdir, 'public_keyset_file')
      with open(public_keyset_filename, 'wb') as f:
        cleartext_keyset_handle.write(
            tink.BinaryKeysetWriter(f), self._public_keyset_handle)
      plaintext_filename = os.path.join(tmpdir, 'plaintext_file')
      with open(plaintext_filename, 'wb') as f:
        f.write(plaintext)
      context_info_filename = os.path.join(tmpdir, 'context_info_file')
      with open(context_info_filename, 'wb') as f:
        f.write(context_info)
      ciphertext_filename = os.path.join(tmpdir, 'ciphertext_file')
      try:
        unused_return_value = subprocess.check_output([
            self._cli, public_keyset_filename, plaintext_filename,
            context_info_filename, ciphertext_filename
        ])
      except subprocess.CalledProcessError as e:
        raise tink.TinkError(e)
      with open(ciphertext_filename, 'rb') as f:
        ciphertext = f.read()
      return ciphertext


class CliHybridDecrypt(hybrid.HybridDecrypt):
  """Wraps a HybridDecrypt CLI binary into a Python primitive."""

  def __init__(self, lang: Text,
               private_keyset_handle: tink.KeysetHandle) -> None:
    self._cli = os.path.join(_tools_path(), _DECRYPT_CLI_PATHS[lang])
    self._private_keyset_handle = private_keyset_handle

  def decrypt(self, ciphertext: bytes, context_info: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as tmpdir:
      private_keyset_filename = os.path.join(tmpdir, 'private_keyset_file')
      with open(private_keyset_filename, 'wb') as f:
        cleartext_keyset_handle.write(
            tink.BinaryKeysetWriter(f), self._private_keyset_handle)
      ciphertext_filename = os.path.join(tmpdir, 'ciphertext_file')
      with open(ciphertext_filename, 'wb') as f:
        f.write(ciphertext)
      context_info_filename = os.path.join(tmpdir, 'context_info_file')
      with open(context_info_filename, 'wb') as f:
        f.write(context_info)
      decrypted_filename = os.path.join(tmpdir, 'decrypted_file')
      try:
        unused_return_value = subprocess.check_output([
            self._cli, private_keyset_filename, ciphertext_filename,
            context_info_filename, decrypted_filename
        ])
      except subprocess.CalledProcessError as e:
        raise tink.TinkError(e)
      with open(decrypted_filename, 'rb') as f:
        plaintext = f.read()
      return plaintext
