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
"""Wraps Sign and Verify CLIs into a Python Tink signature classes."""

# Placeholder for import for type annotations

import os
import subprocess
import tempfile

from typing import Text

import tink
from tink import signature
from tink import testonly_cleartext_keyset_handle


# All languages that have an AEAD CLI.
LANGUAGES = ('cc', 'go', 'java', 'python')

# Path are relative to tools directory.
_SIGN_CLI_PATHS = {
    'cc': 'testing/cc/public_key_sign_cli_cc',
    'go': 'testing/go/public_key_sign_cli_go',
    'java': 'testing/public_key_sign_cli_java',
    'python': 'testing/python/public_key_sign_cli_python',
}

_VERIFY_CLI_PATHS = {
    'cc': 'testing/cc/public_key_verify_cli_cc',
    'go': 'testing/go/public_key_verify_cli_go',
    'java': 'testing/public_key_verify_cli_java',
    'python': 'testing/python/public_key_verify_cli_python',
}


def _tools_path() -> Text:
  util_path = os.path.dirname(os.path.abspath(__file__))
  return os.path.dirname(os.path.dirname(os.path.dirname(util_path)))


class CliPublicKeySign(signature.PublicKeySign):
  """Wraps a PublicKeySign CLI binary into a Python primitive."""

  def __init__(self, lang: Text,
               private_keyset_handle: tink.KeysetHandle) -> None:
    self.lang = lang
    self._cli = os.path.join(_tools_path(), _SIGN_CLI_PATHS[lang])
    self._private_keyset_handle = private_keyset_handle

  def sign(self, message: bytes) -> bytes:
    with tempfile.TemporaryDirectory() as tmpdir:
      private_keyset_filename = os.path.join(tmpdir, 'private_keyset_file')
      with open(private_keyset_filename, 'wb') as f:
        testonly_cleartext_keyset_handle.write(
            tink.BinaryKeysetWriter(f), self._private_keyset_handle)
      message_filename = os.path.join(tmpdir, 'message_filename')
      with open(message_filename, 'wb') as f:
        f.write(message)
      output_filename = os.path.join(tmpdir, 'output_file')
      try:
        unused_return_value = subprocess.check_output([
            self._cli, private_keyset_filename, message_filename,
            output_filename
        ])
      except subprocess.CalledProcessError as e:
        raise tink.TinkError(e)
      with open(output_filename, 'rb') as f:
        output = f.read()
      return output


class CliPublicKeyVerify(signature.PublicKeyVerify):
  """Wraps a PublicKeyVerify CLI binary into a Python primitive."""

  def __init__(self, lang: Text,
               public_keyset_handle: tink.KeysetHandle) -> None:
    self.lang = lang
    self._cli = os.path.join(_tools_path(), _VERIFY_CLI_PATHS[lang])
    self._public_keyset_handle = public_keyset_handle

  def verify(self, sign: bytes, data: bytes) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
      public_keyset_filename = os.path.join(tmpdir, 'public_keyset_file')
      with open(public_keyset_filename, 'wb') as f:
        testonly_cleartext_keyset_handle.write(
            tink.BinaryKeysetWriter(f), self._public_keyset_handle)
      signature_filename = os.path.join(tmpdir, 'signature_file')
      with open(signature_filename, 'wb') as f:
        f.write(sign)
      message_filename = os.path.join(tmpdir, 'message_file')
      with open(message_filename, 'wb') as f:
        f.write(data)
      output_filename = os.path.join(tmpdir, 'output_file')
      try:
        unused_return_value = subprocess.check_output([
            self._cli, public_keyset_filename, signature_filename,
            message_filename, output_filename
        ])
      except subprocess.CalledProcessError as e:
        raise tink.TinkError(e)
      with open(output_filename, 'rb') as f:
        output = f.read()
      if output != b'valid':
        raise tink.TinkError('verification failed')
      return None
