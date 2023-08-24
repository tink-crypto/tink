# Copyright 2019 Google LLC
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
from typing import Optional, Tuple
import urllib
import hvac
import tink
from tink import aead
from tink.aead import _kms_aead_key_manager


VAULT_KEYURI_PREFIX = 'hcvault://'

"""
_endpoint_paths transforms key_uri into the Vault transit encrypt and decrypt
paths. The keyURL is expected to end in "/{mount}/keys/{keyName}". For
example, the keyURL "hcvault:///transit/keys/key-foo" will be transformed to
"transit/encrypt/key-foo" and "transit/decrypt/key-foo", and
"hcvault://my-vault.example.com/teams/billing/service/cipher/keys/key-bar"
will be transformed into
"hcvault://my-vault.example.com/teams/billing/service/cipher/encrypt/key-bar"
and
"hcvault://my-vault.example.com/teams/billing/service/cipher/decrypt/key-bar".
"""

def _endpoint_paths(key_uri: str) -> Tuple[str, str]:
  u = urllib.parse.urlparse(key_uri)
  if u.scheme != "hcvault":
    raise tink.TinkError('malformed URL')
  
  escaped_path = urllib.parse.quote(u.path)
  parts = escaped_path.split('/')
  parts = [x for x in parts if x]
  return parts[:1][0], parts[-1:][0] # First entry i.e. "transit" and last entry i.e. "key-bar"

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