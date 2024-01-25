# Copyright 2021 Google LLC
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
"""A client for Fake KMS."""

import base64
from typing import Optional

import tink
from tink import aead
from tink import secret_key_access


FAKE_KMS_PREFIX = 'fake-kms://'


class FakeKmsClient(tink.KmsClient):
  """A fake KMS client."""

  def __init__(self, key_uri: Optional[str] = None):
    if not key_uri:
      self._key_uri = None
    elif key_uri.startswith(FAKE_KMS_PREFIX):
      self._key_uri = key_uri
    else:
      raise tink.TinkError('invalid key URI')

  def does_support(self, key_uri: str) -> bool:
    if not key_uri.startswith(FAKE_KMS_PREFIX):
      return False
    if not self._key_uri:
      return True
    return key_uri == self._key_uri

  def get_aead(self, key_uri: str) -> aead.Aead:
    if not key_uri.startswith(FAKE_KMS_PREFIX):
      raise tink.TinkError('invalid key URI')
    key_id = key_uri[len(FAKE_KMS_PREFIX) :]
    serialized_key = base64.urlsafe_b64decode(key_id.encode('utf-8') + b'===')
    handle = tink.proto_keyset_format.parse(
        serialized_key, secret_key_access.TOKEN
    )
    return handle.primitive(aead.Aead)


def register_client(key_uri=None, credentials_path=None) -> None:
  """Registers a fake KMS client."""
  _ = credentials_path
  tink.register_kms_client(FakeKmsClient(key_uri))
