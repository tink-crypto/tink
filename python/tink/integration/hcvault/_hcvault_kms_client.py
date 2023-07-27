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


class _HcVaultKmsAead(aead.Aead):
  """Implements the Aead interface for AWS KMS."""

  def __init__(self, client: hvac.Client, key_uri: str) -> None:
    self.client = client
    mount_point, key_name = self.get_endpoint_paths(key_uri)
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
    
  """
  get_endpoint_paths transforms key_uri into the Vault transit encrypt and decrypt
  paths. The keyURL is expected to end in "/{mount}/keys/{keyName}". For
  example, the keyURL "hcvault:///transit/keys/key-foo" will be transformed to
  "transit/encrypt/key-foo" and "transit/decrypt/key-foo", and
  "hcvault://my-vault.example.com/teams/billing/service/cipher/keys/key-bar"
  will be transformed into
  "hcvault://my-vault.example.com/teams/billing/service/cipher/encrypt/key-bar"
  and
  "hcvault://my-vault.example.com/teams/billing/service/cipher/decrypt/key-bar".
  """

  def get_endpoint_paths(self, key_uri: str):
    u = urllib.parse.urlparse(key_uri)
    if u.scheme != "hcvault":
      raise tink.TinkError('malformed URL')
    
    escaped_path = urllib.parse.quote(u.path)
    parts = escaped_path.split('/')
    parts = [x for x in parts if x]
    return parts[:1][0], parts[-1:][0] # First entry i.e. "transit" and last entry i.e. "key-bar"

class HcVaultKmsClient(_kms_aead_key_manager.KmsClient):
  """Basic Hashicorp Vault client for AEAD."""

  def __init__(self, key_uri: str, token: str, https=True, verify=True, client_certs: Tuple[str, str] = None, namespace: Optional[str] = None):
    """Creates a new HcVaultKmsClient that is bound to the key specified in 'key_uri'.

    Args:
      key_uri: The URI of the key the client should be bound to.
      token: The token used to auth with vault
      https: Whether to connect via HTTPS or HTTP, default to HTTPS (can use HTTP for dev environments)
      verify: Whether to verify the HTTPS cert, default behaviour is to verify but can be turned off for dev environments

    Raises:
      ValueError: If the path or credentials token is invalid.
      TinkError: If the key uri is not valid.
    """

    if not key_uri or not self.does_support(key_uri):
      raise tink.TinkError('invalid key URI')
    
    if not token:
      raise ValueError('no login token provided')

    parsed_uri = urllib.parse.urlparse(key_uri)
    self.vault_url = f'{"http" if not https else "https"}://{parsed_uri.netloc}'
    self.key_uri = parsed_uri.path
    self.token = token
    self.client = hvac.Client(url=self.vault_url, token=self.token, verify=verify, client_certs=client_certs, namespace=namespace)
    if not self.client.is_authenticated():
      raise tink.TinkError('failed to authenticate with vault')
    

  def does_support(self, key_uri: str) -> bool:
    """Returns true if this client supports KMS key specified in 'key_uri'.

    Args:
      key_uri: Text, URI of the key to be checked.

    Returns: A boolean value which is true if the key is supported and false
      otherwise.
    """
    if not key_uri.startswith(VAULT_KEYURI_PREFIX):
      return False
    return True

  def get_aead(self, key_uri: str) -> aead.Aead:
    """Returns an Aead-primitive backed by KMS key specified by 'key_uri'.

    Args:
      key_uri: Text, URI of the key which should be used.

    Returns:
      An AEAD primitive which uses the specified key.

    Raises:
      TinkError: If the key_uri is not supported.
    """
    if not self.does_support(key_uri):
      raise tink.TinkError('This client does not support key %s' % key_uri)
  
    return _HcVaultKmsAead(self.client, key_uri)

  @classmethod
  def register_client(cls, key_uri: str, token: str, https=True, verify=True, client_certs: Tuple[str, str] = None, namespace: Optional[str]=None) -> None:
    """Registers the KMS client internally."""
    _kms_aead_key_manager.register_kms_client(  # pylint: disable=protected-access
      HcVaultKmsClient(key_uri, token, https=https, verify=verify, client_certs=client_certs, namespace=namespace)
    )
