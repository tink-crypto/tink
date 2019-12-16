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

"""This module implement a client for the Google Cloud KMS."""

from __future__ import absolute_import
from __future__ import division
from __future__ import google_type_annotations
from __future__ import print_function


class GcpKmsClient(object):
  """Basic GCP client for AEAD."""

  def __init__(self, key_uri: string, credentials_path: string):
    """Creates a new GcpKmsClient that is bound to the key specified in 'key_uri'.

    Uses the specifed credentials when communicating with the KMS. Either of
    arguments can be empty.

    If 'key_uri' is empty, then the client is not bound to any particular key.
    If 'credential_path' is empty, then default credentials will be used.

    Args:
      key_uri: string, URI of the key the client should be bound to.
      credentials_path: string, Path to the file with the access credentials.
    """
    self.key_uri = key_uri
    self.credentials_path = credentials_path

  def does_support(self, key_uri: string) -> bool:
    """Returns true iff this client supports KMS key specified in 'key_uri'.

    Args:
      key_uri: string, URI of the key to be checked.

    Return:
      A boolean value which is true if the key is supported and false otherwise.
    """
    if not key_uri:
      return False

    return True

  def get_aead(self, key_uri: string):
    """Returns an Aead-primitive backed by KMS key specified by 'key_uri'.

    Args:
      key_uri: string, URI of the key which should be used.

    Returns:
      The AEAD object...
    """

    if not key_uri:
      return None
    return None
