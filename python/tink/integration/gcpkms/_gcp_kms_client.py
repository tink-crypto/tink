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

from tink import aead
from tink import core
from tink.aead import _kms_aead_key_manager
from tink.cc.pybind import tink_bindings

GCP_KEYURI_PREFIX = 'gcp-kms://'


class GcpKmsClient(_kms_aead_key_manager.KmsClient):
  """Basic GCP client for AEAD."""

  def __init__(self, key_uri: Optional[str], credentials_path: str):
    """Creates a new GcpKmsClient that is bound to the key specified in 'key_uri'.

    Uses the specified credentials when communicating with the KMS.

    Args:
      key_uri: The URI of the key the client should be bound to. If it is None
          or empty, then the client is not bound to any particular key.
      credentials_path: Path to the file with the access credentials. If it is
          empty, then default credentials will be used.

    Raises:
      ValueError: If the path or filename of the credentials is invalid.
      TinkError: If the key uri is not valid.
    """

    if not key_uri:
      self._key_uri = ''
    elif key_uri.startswith(GCP_KEYURI_PREFIX):
      self._key_uri = key_uri
    else:
      raise core.TinkError('Invalid key_uri.')

    # Use the C++ GCP KMS client
    self.cc_client = tink_bindings.GcpKmsClient(self._key_uri, credentials_path)

  def does_support(self, key_uri: str) -> bool:
    """Returns true iff this client supports KMS key specified in 'key_uri'.

    Args:
      key_uri: URI of the key to be checked.

    Returns:
      A boolean value which is true if the key is supported and false otherwise.
    """
    return self.cc_client.does_support(key_uri)

  @core.use_tink_errors
  def get_aead(self, key_uri: str) -> aead.Aead:
    """Returns an Aead-primitive backed by KMS key specified by 'key_uri'.

    Args:
      key_uri: URI of the key which should be used.

    Returns:
      An Aead object.
    """

    return aead.AeadCcToPyWrapper(self.cc_client.get_aead(key_uri))

  @classmethod
  def register_client(cls, key_uri, credentials_path) -> None:
    """Registers the KMS client internally."""
    _kms_aead_key_manager.register_kms_client(  # pylint: disable=protected-access
        GcpKmsClient(key_uri, credentials_path)
    )
