# Copyright 2023 Google LLC
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
"""Integration tests for Tink Python's HashiCorp Vault KMS integration."""

import base64
import os

from absl.testing import absltest
import hvac

import tink
from tink import aead
from tink.integration import hcvault


_VAULT_TOKEN = os.getenv('VAULT_TOKEN', '')  # Your auth token
_VAULT_ADDR = os.getenv('VAULT_ADDR', '')

_BAD_TOKEN = 'notavalidtoken'

# Replace this with your vault URI
_KEY_PATH = 'transit/keys/key-1'


def setUpModule():
  aead.register()


def _corrupt(value: bytes, i: int) -> bytes:
  """Corrupts a byte in `value` at a given index `i`."""
  assert i >= 0 and i < len(value)
  tmp_value = list(value)
  tmp_value[i] ^= 2
  return bytes(tmp_value)


class HcVaultAeadTest(absltest.TestCase):

  def setUp(self):
    super().setUp()
    self.client = hvac.Client(url=_VAULT_ADDR, token=_VAULT_TOKEN, verify=False)

  def test_encrypt_decrypt(self):
    vaultaead = hcvault.new_aead(_KEY_PATH, self.client)

    plaintext = bytes(i for i in range(256))
    ciphertext = vaultaead.encrypt(plaintext, associated_data=b'')
    self.assertEqual(
        plaintext, vaultaead.decrypt(ciphertext, associated_data=b'')
    )

  def test_corrupted_ciphertext(self):
    vaultaead = hcvault.new_aead(_KEY_PATH, self.client)

    plaintext = b'helloworld'
    ciphertext = vaultaead.encrypt(plaintext, b'')
    self.assertEqual(plaintext, vaultaead.decrypt(ciphertext, b''))

    # The returned ciphertext is of the form:
    #           vault:v{N}:Base64(IV+Ciphertext)
    vault, version, iv_and_ciphertext = ciphertext.decode().split(':')
    # Corrupt vault.
    for i in range(len(vault)):
      corrupted_vault = _corrupt(vault.encode(), i)
      with self.assertRaises(tink.TinkError):
        vaultaead.decrypt(
            f'{corrupted_vault}:{version}:{iv_and_ciphertext}'.encode(), b''
        )

    # Corrupt the version.
    for i in range(len(version)):
      corrupted_version = _corrupt(version.encode(), i)
      with self.assertRaises(tink.TinkError):
        vaultaead.decrypt(
            f'{vault}:{corrupted_version}:{iv_and_ciphertext}'.encode(), b''
        )

    # Corrupt the ciphertext.
    # In this case we corrupt the decoded string, then encode back to Base64.
    iv_and_ciphertext = base64.b64decode(iv_and_ciphertext.encode())
    for i in range(len(iv_and_ciphertext)):
      corrupted_iv_and_ciphertext = base64.b64encode(
          _corrupt(iv_and_ciphertext, i)
      )
      with self.assertRaises(tink.TinkError):
        vaultaead.decrypt(
            f'{vault}:{version}:{corrupted_iv_and_ciphertext}', b''
        )

  def test_encrypt_with_bad_client(self):
    bad_client = hvac.Client(url=_VAULT_ADDR, token=_BAD_TOKEN, verify=False)
    vaultaead = hcvault.new_aead(_KEY_PATH, bad_client)
    with self.assertRaises(tink.TinkError):
      vaultaead.encrypt(plaintext=b'hello', associated_data=b'')


if __name__ == '__main__':
  absltest.main()
