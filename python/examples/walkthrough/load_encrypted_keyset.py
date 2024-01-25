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
"""Example to showcase how to load an encrypted keyset."""
# [START tink_walkthrough_load_encrypted_keyset]
import tink

from tink import aead


def LoadEncryptedKeyset(json_serialized_encrypted_keyset: str, kms_key_uri: str,
                        associated_data: bytes) -> tink.KeysetHandle:
  r"""Loads a JSON-serialized keyset that was encrypted with a KMS.

  Prerequisites for this example:
  - Register AEAD implementations of Tink.
  - Register a KMS client for the given URI prefix. Tink Python provides
    awskms.AwsKmsClient.register_client() and
    gcpkms.GcpKmsClient.register_client() for AWS-KMS and Google Cloud KMS
    respectively.
  - Create a KMS encrypted keyset, for example using Tinkey with Google Cloud
    KMS:

    tinkey create-keyset --key-template AES128_GCM \
      --out-format json --out encrypted_aead_keyset.json \
      --master-key-uri gcp-kms://<KMS key uri> \
      --credentials gcp_credentials.json

  Args:
    json_serialized_encrypted_keyset: JSON serialized keyset.
    kms_key_uri: The URI of the KMS key to use to decrypt the keyset.
    associated_data: Associated data.

  Returns:
    A handle to the loaded keyset.

  Raises:
    tink.TinkError in case of errors.
  """
  # To obtain a primitive that uses the KMS to encrypt/decrypt we simply create
  # keyset from the appropriate template and get an AEAD primitive from it.
  template = aead.aead_key_templates.create_kms_aead_key_template(kms_key_uri)
  keyset_handle = tink.new_keyset_handle(template)
  kms_aead = keyset_handle.primitive(aead.Aead)
  return tink.json_proto_keyset_format.parse_encrypted(
      json_serialized_encrypted_keyset, kms_aead, associated_data
  )


# [END tink_walkthrough_load_encrypted_keyset]
