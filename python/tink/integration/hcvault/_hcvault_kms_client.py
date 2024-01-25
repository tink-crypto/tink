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

"""A client for Hashicorp Vault."""

import base64
from typing import Tuple
import urllib
import hvac
import tink
from tink import aead


def _endpoint_paths(key_uri: str) -> Tuple[str, str]:
  """Transforms key_uri into Vault transit encrypt/decrypt mount point and transit key.

  The key_uri is expected to end in "/{mount}/keys/{keyName}". For example, the
  key_uri "hcvault:///transit/keys/key-foo" will be transformed to
  "transit" and "key-foo", and
  "hcvault://my-vault.example.com/teams/billing/service/cipher/keys/key-bar"
  will be transformed into "teams/billing/service/cipher" and "key-bar".

  Args:
    key_uri: Key URI
  Returns:
    Vault transit encryp/decrypt mount point and transit key.
  """
  u = urllib.parse.urlparse(key_uri)

  escaped_path = urllib.parse.quote(u.path)
  parts = escaped_path.split('/')
  length = len(parts)
  if length < 4 or parts[length - 2] != 'keys':
    raise tink.TinkError('malformed URL')

  parts[length - 2] = ''
  parts = [x for x in parts if x]
  return (
      '/'.join(parts[:-1]),
      parts[-1:][0],
  )  # First entry i.e. "transit" and last entry i.e. "key-bar"


def create_aead(key_uri: str, client: hvac.Client) -> aead.Aead:
  return _HcVaultKmsAead(client, key_uri)


class _HcVaultKmsAead(aead.Aead):
  """Implements the Aead interface for Hashicorp Vault."""

  def __init__(self, client: hvac.Client, key_uri: str) -> None:
    self.client = client
    mount_point, key_name = _endpoint_paths(key_uri)
    self.key_name = key_name
    self.mount_point = mount_point

  def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
    try:
      response = self.client.secrets.transit.encrypt_data(
          name=self.key_name,
          plaintext=base64.urlsafe_b64encode(plaintext).decode(),
          context=base64.urlsafe_b64encode(associated_data).decode(),
          mount_point=self.mount_point,
      )
      return response['data']['ciphertext'].encode()
    except Exception as e:
      raise tink.TinkError(e)

  def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes:
    try:
      response = self.client.secrets.transit.decrypt_data(
          name=self.key_name,
          ciphertext=ciphertext.decode(),
          context=base64.urlsafe_b64encode(associated_data).decode(),
          mount_point=self.mount_point,
      )
      return base64.urlsafe_b64decode(response['data']['plaintext'])
    except Exception as e:
      raise tink.TinkError(e)
