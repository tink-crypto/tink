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

"""Provides AEAD using the AWS KMS client.

Currently works only in Python3 (see Bug 146480447)
"""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

import boto3
from botocore.exceptions import ClientError

from typing import Text

from tink.python.aead import aead


class AwsKmsAead(aead.Aead):
  """Provides AEAD primitive through AWS client."""

  def __init__(self, key_name: Text, client: boto3.client):
    """Creates new AwsKmsAead bound to a key.

    Args:
      key_name: Text, ARN key
      client: boto3.client, The AWS KMS client to talk to.
    """
    self.key_name = key_name
    self.client = client

  def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
    if associated_data:
      ad = {'additionalData': associated_data.decode()}

    try:
      if associated_data:
        response = self.client.encrypt(KeyId=self.key_name,
                                       Plaintext=plaintext,
                                       EncryptionContext=ad)
      else:
        response = self.client.encrypt(KeyId=self.key_name,
                                       Plaintext=plaintext)
    except (ValueError, ClientError):
      # TODO(b/146515546): Change to tink_error when its moved to pybind11
      raise ValueError('Encryption failed inside AWS client.')

    return response['CiphertextBlob']

  def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes:
    if associated_data:
      ad = {'additionalData': associated_data.decode()}

    try:
      if associated_data:
        response = self.client.decrypt(KeyId=self.key_name,
                                       CiphertextBlob=ciphertext,
                                       EncryptionContext=ad)
      else:
        response = self.client.decrypt(KeyId=self.key_name,
                                       CiphertextBlob=ciphertext)
    except ClientError:
      # TODO(b/146515546): Change to tink_error when its moved to pybind11
      raise ValueError('Decryption failed inside AWS client.')

    return response['Plaintext']
