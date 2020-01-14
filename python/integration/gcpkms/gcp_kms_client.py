# Copyright 2019 Google LLC.
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

"""A client for Google Cloud KMS.

Currently works only in Python3 (see Bug 146480447)
"""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from typing import Text
from google.auth import default
from google.cloud import kms_v1
from google.oauth2 import service_account

from tink.python.aead import aead
from tink.python.integration.gcpkms.gcp_kms_aead import GcpKmsAead

GCP_KEYURI_PREFIX = "gcp-kms://"


class GcpKmsClient(object):
  """Basic GCP client for AEAD."""

  def __init__(self, key_uri: Text, credentials_path: Text):
    """Creates a new GcpKmsClient that is bound to the key specified in 'key_uri'.

    Uses the specifed credentials when communicating with the KMS. Either of
    arguments can be empty.

    If 'key_uri' is empty, then the client is not bound to any particular key.
    If 'credential_path' is empty, then default credentials will be used.

    Args:
      key_uri: Text, URI of the key the client should be bound to.
      credentials_path: Text, Path to the file with the access credentials.

    Raises:
      FileNotFoundError: If the path to the credentials is invalid.
    """

    if not key_uri:
      self.key_uri = GCP_KEYURI_PREFIX
    elif key_uri.startswith(GCP_KEYURI_PREFIX):
      self.key_uri = key_uri
    else:
      # TODO(kste): Change to tink_error when its moved to pybind11
      raise ValueError

    if not credentials_path:
      # Use GCP KMS client with default credentials
      credentials = default()
    else:
      credentials = service_account.Credentials.from_service_account_file(
          filename=credentials_path
      )

    self.client = kms_v1.KeyManagementServiceClient(credentials=credentials)

  def does_support(self, key_uri: Text) -> bool:
    """Returns true iff this client supports KMS key specified in 'key_uri'.

    Args:
      key_uri: Text, URI of the key to be checked.

    Returns:
      A boolean value which is true if the key is supported and false otherwise.
    """
    return key_uri.startswith(self.key_uri)

  def get_aead(self, key_uri: Text) -> aead.Aead:
    """Returns an Aead-primitive backed by KMS key specified by 'key_uri'.

    Args:
      key_uri: Text, URI of the key which should be used.

    Returns:
      The AEAD object...
    """

    key_name = key_uri[len(GCP_KEYURI_PREFIX):]
    return GcpKmsAead(key_name, self.client)
