# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS-IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Example to showcase how to create a keyset."""
# [START tink_walkthrough_write_keyset]
from typing import TextIO

import tink
from tink import aead


def GetKmsAead(kms_kek_uri: str) -> aead.Aead:
  """Returns an AEAD primitive from a KMS Key Encryption Key URI."""
  # To obtain a primitive that uses the KMS to encrypt/decrypt we simply create
  # keyset from the appropriate template and get an AEAD primitive from it.
  template = aead.aead_key_templates.create_kms_aead_key_template(kms_kek_uri)
  kms_aead_keyset_handle = tink.new_keyset_handle(template)
  return kms_aead_keyset_handle.primitive(aead.Aead)


def WriteEncryptedKeyset(keyset_handle: tink.KeysetHandle,
                         text_io_stream: TextIO,
                         kms_kek_uri: str,
                         associated_data: bytes = b'') -> None:
  """Encrypts keyset_hanlde with a KMS and writes it to text_io_stream as JSON.

  The keyset is encrypted with a KMS using the KMS key kms_kek_uri.

  Prerequisites:
    - Register AEAD implementations of Tink.
    - Register a KMS client that can use kms_kek_uri.
    - Create a keyset and obtain a handle to it.

  Args:
    keyset_handle: Keyset to write.
    text_io_stream: I/O stream where writng the Keyset to.
    kms_kek_uri: URI of the KMS key to use to encrypt the keyset.
    associated_data: Associated data to which tie the ciphertext.

  Raises:
    tink.TinkError in case of errors.
  """
  keyset_handle.write_with_associated_data(
      tink.JsonKeysetWriter(text_io_stream), GetKmsAead(kms_kek_uri),
      associated_data)


# [END tink_walkthrough_write_keyset]
