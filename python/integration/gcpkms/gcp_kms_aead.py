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

"""Provides AEAD using the Google Cloud KMS client.

Currently works only in Python3 (see Bug 146480447)
"""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from typing import Text
from google.api_core.exceptions import GoogleAPICallError
from google.api_core.exceptions import RetryError
from google.cloud import kms_v1

from tink.python.aead import aead


class GcpKmsAead(aead.Aead):
  """Provides an AEAD primitive through GCP client."""

  def __init__(self, key_name: Text, client: kms_v1.KeyManagementServiceClient):
    """Creates a new GcpKmsAead bound to a key.

    Args:
      key_name: Text, Valid values must have have the format
        projects/*/locations/*/keyRings/*/cryptoKeys/*.
        See https://cloud.google.com/kms/docs/object-hierarchy for more info.
      client: kms_v1.KeyManagmentServiceClient, The Google Cloud KMS client
        to talk to.
    """
    self.key_name = key_name
    self.client = client

  def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
    try:
      response = self.client.encrypt(self.key_name,
                                     plaintext,
                                     associated_data)
    except (GoogleAPICallError, RetryError, ValueError):
      # TODO(kste): Change to tink_error when its moved to pybind11
      raise ValueError("Encryption failed inside GCP client.")

    return response.ciphertext

  def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes:
    try:
      response = self.client.decrypt(self.key_name, ciphertext, associated_data)
    except (GoogleAPICallError, RetryError, ValueError):
      # TODO(kste): Change to tink_error when its moved to pybind11
      raise ValueError("Decryption failed inside GCP client.")

    return response.plaintext
