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
"""A client for Google Cloud KMS."""

from typing import Optional
import warnings

from google.api_core import exceptions as core_exceptions
from google.cloud import kms_v1
from google.oauth2 import service_account

import tink
from tink import aead

GCP_KEYURI_PREFIX = 'gcp-kms://'


class _GcpKmsAead(aead.Aead):
  """Implements the Aead interface for GCP KMS."""

  def __init__(
      self, client: kms_v1.KeyManagementServiceClient, name: str
  ) -> None:
    self.client = client
    self.name = name

  def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
    try:
      response = self.client.encrypt(
          request=kms_v1.types.service.EncryptRequest(
              name=self.name,
              plaintext=plaintext,
              additional_authenticated_data=associated_data,
          )
      )
      return response.ciphertext
    except core_exceptions.GoogleAPIError as e:
      raise tink.TinkError(e)

  def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes:
    try:
      response = self.client.decrypt(
         request=kms_v1.types.service.DecryptRequest(
             name=self.name,
             ciphertext=ciphertext,
             additional_authenticated_data=associated_data
         )
      )
      return response.plaintext
    except core_exceptions.GoogleAPIError as e:
      raise tink.TinkError(e)


class GcpKmsClient(tink.KmsClient):
  """Basic GCP client for AEAD."""

  def __init__(
      self, key_uri: Optional[str], credentials_path: Optional[str]
  ) -> None:
    """Creates a new GcpKmsClient that is bound to the key specified in 'key_uri'.

    Uses the specified credentials when communicating with the KMS.

    Args:
      key_uri: The URI of the key the client should be bound to. If it is None
          or empty, then the client is not bound to any particular key.
      credentials_path: Path to the file with the access credentials. If it is
          None or empty, then default credentials will be used.

    Raises:
      ValueError: If the path or filename of the credentials is invalid.
      TinkError: If the key uri is not valid.
    """

    if not key_uri:
      self._key_uri = None
    elif key_uri.startswith(GCP_KEYURI_PREFIX):
      self._key_uri = key_uri
    else:
      raise tink.TinkError('Invalid key_uri.')
    if not credentials_path:
      credentials_path = ''
    if not credentials_path:
      self._client = kms_v1.KeyManagementServiceClient()
      return
    credentials = service_account.Credentials.from_service_account_file(
        credentials_path
    )
    self._client = kms_v1.KeyManagementServiceClient(credentials=credentials)

  def does_support(self, key_uri: str) -> bool:
    """Returns true iff this client supports KMS key specified in 'key_uri'.

    Args:
      key_uri: URI of the key to be checked.

    Returns:
      A boolean value which is true if the key is supported and false otherwise.
    """
    if not self._key_uri:
      return key_uri.startswith(GCP_KEYURI_PREFIX)
    return key_uri == self._key_uri

  def get_aead(self, key_uri: str) -> aead.Aead:
    """Returns an Aead-primitive backed by KMS key specified by 'key_uri'.

    Args:
      key_uri: URI of the key which should be used.

    Returns:
      An Aead object.
    """
    if self._key_uri and self._key_uri != key_uri:
      raise tink.TinkError(
          'This client is bound to %s and cannot use key %s'
          % (self._key_uri, key_uri)
      )
    if not key_uri.startswith(GCP_KEYURI_PREFIX):
      raise tink.TinkError('Invalid key_uri.')
    key_id = key_uri[len(GCP_KEYURI_PREFIX) :]
    return _GcpKmsAead(self._client, key_id)

  # Deprecated. It is preferable to not register KMS clients. Instead, create
  # a KMS AEAD with
  # kms_aead = gcpkms.GcpKmsClient(key_uri, credentials_path).get_aead(key_uri)
  # and then use it to encrypt a keyset with KeysetHandle.write, or to create
  # an envelope AEAD using aead.KmsEnvelopeAead.
  @classmethod
  def register_client(
      cls, key_uri: Optional[str], credentials_path: Optional[str]
  ) -> None:
    """Registers the KMS client internally."""
    warnings.warn(
        'The "gcpkms.GcpKmsClient.register_client" function is deprecated.',
        DeprecationWarning,
        2,
    )
    tink.register_kms_client(GcpKmsClient(key_uri, credentials_path))
