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
"""Python wrapper for Tinkey CLI."""

# Placeholder for import for type annotations

import os
import subprocess
import tempfile

import tink
from tink import cleartext_keyset_handle

AEAD_KEY_TEMPLATES = ('AES128_GCM', 'AES256_GCM', 'AES128_CTR_HMAC_SHA256',
                      'AES256_CTR_HMAC_SHA256', 'XCHACHA20_POLY1305',
                      'AES128_EAX', 'AES256_EAX', 'CHACHA20_POLY1305')

DAEAD_KEY_TEMPLATE = 'AES256_SIV'

HYBRID_KEY_TEMPLATES = (
    'ECIES_P256_HKDF_HMAC_SHA256_AES128_CTR_HMAC_SHA256',
    'ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM')

MAC_KEY_TEMPLATES = ('HMAC_SHA256_128BITTAG', 'HMAC_SHA256_256BITTAG',
                     'HMAC_SHA512_256BITTAG', 'HMAC_SHA512_512BITTAG')

# Path is relative to tools directory
_TINKEY_CLI_PATH = 'tinkey/tinkey'


def _tools_path():
  util_path = os.path.dirname(os.path.abspath(__file__))
  return os.path.dirname(os.path.dirname(os.path.dirname(util_path)))


def generate_keyset_handle(key_template) -> tink.KeysetHandle:
  """Generates a keyset handle from a key templates."""
  with tempfile.TemporaryDirectory() as tmpdir:
    keyset_filename = os.path.join(tmpdir, 'keyset_file')
    cli_path = os.path.join(_tools_path(), _TINKEY_CLI_PATH)
    unused_return_value = subprocess.check_output([
        cli_path, 'create-keyset',
        '--key-template', key_template,
        '--out-format', 'BINARY',
        '--out', keyset_filename
    ])
    with open(keyset_filename, 'rb') as f:
      keyset_data = f.read()
    return cleartext_keyset_handle.read(tink.BinaryKeysetReader(keyset_data))


def public_keyset_handle(private_keyset_handle) -> tink.KeysetHandle:
  """Generates a public keyset handle from a private one."""
  with tempfile.TemporaryDirectory() as tmpdir:
    cli_path = os.path.join(_tools_path(), _TINKEY_CLI_PATH)
    private_keyset_filename = os.path.join(tmpdir, 'private_keyset_file')
    with open(private_keyset_filename, 'wb') as f:
      cleartext_keyset_handle.write(
          tink.BinaryKeysetWriter(f), private_keyset_handle)
    public_keyset_filename = os.path.join(tmpdir, 'public_keyset_file')
    unused_return_value = subprocess.check_output([
        cli_path, 'create-public-keyset',
        '--in-format', 'BINARY',
        '--in', private_keyset_filename,
        '--out-format', 'BINARY',
        '--out', public_keyset_filename,
    ])
    with open(public_keyset_filename, 'rb') as f:
      public_keyset_data = f.read()
    return cleartext_keyset_handle.read(
        tink.BinaryKeysetReader(public_keyset_data))
