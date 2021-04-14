# Copyright 2021 Google LLC
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
# [START gcs-envelope-aead-example]
"""A command-line utility for encrypting small files with envelope encryption and uploading the results to GCS.

It requires the following arguments:
  mode: "encrypt" or "decrypt" to indicate if you want to encrypt or decrypt.
  kek-uri: Use this Cloud KMS' key as the key-encryption key for envelope
        encryption.
  gcp-credential-file: Use this JSON credential file to connect to
        Cloud KMS and GCS.
  gcp-project-id: The ID of the GCP project hosting the GCS blobs that you want
        to encrypt or decrypt.

When mode is "encrypt", it takes the following additional arguments:
  local-input-file: Read the plaintext from this local file.
  gcs-output-blob: Write the encryption result to this blob in GCS. The
         encryption result is bound to the location of this blob. That is, if
         you rename or move it to a different bucket, decryption will fail.

When mode is "decrypt", it takes the following additional arguments:
  gcs-input-blob: Read the ciphertext from this blob in GCS.
  local-output-file: Write the decryption result to this local file.
"""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from absl import app
from absl import logging
from google.cloud import storage

import tink
from tink import aead
from tink.integration import gcpkms


_GCS_PATH_PREFIX = 'gs://'


def main(argv):
  if len(argv) != 7:
    raise app.UsageError(
        'Expected 6 arguments, got %d.\n'
        'Usage: %s encrypt/decrypt kek-uri gcp-credential-file gcp-project-id'
        'input-file output-file' % (len(argv) - 1, argv[0]))

  mode = argv[1]
  kek_uri = argv[2]
  gcp_credential_file = argv[3]

  # Initialise Tink
  try:
    aead.register()
  except tink.TinkError as e:
    logging.error('Error initialising Tink: %s', e)
    return 1

  # Read the GCP credentials and setup client
  try:
    gcpkms.GcpKmsClient.register_client(kek_uri, gcp_credential_file)
  except tink.TinkError as e:
    logging.error('Error initializing GCP client: %s', e)
    return 1

  # Create envelope AEAD primitive using AES256 GCM for encrypting the data
  try:
    template = aead.aead_key_templates.create_kms_envelope_aead_key_template(
        kek_uri=kek_uri,
        dek_template=aead.aead_key_templates.AES256_GCM)
    handle = tink.KeysetHandle.generate_new(template)
    env_aead = handle.primitive(aead.Aead)
  except tink.TinkError as e:
    logging.error('Error creating primitive: %s', e)
    return 1

  storage_client = storage.Client.from_service_account_json(gcp_credential_file)

  if mode == 'encrypt':
    input_file_path = argv[5]
    gcs_blob_path = argv[6]
    associated_data = gcs_blob_path.encode('utf-8')
    with open(input_file_path, 'rb') as input_file:
      output_data = env_aead.encrypt(input_file.read(), associated_data)

    bucket_name, object_name = _get_bucket_and_object(gcs_blob_path)
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(object_name)
    blob.upload_from_string(output_data)

  elif mode == 'decrypt':
    gcs_blob_path = argv[5]
    ouput_file_path = argv[6]
    bucket_name, object_name = _get_bucket_and_object(gcs_blob_path)
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.get_blob(object_name)
    ciphertext = blob.download_as_string()
    associated_data = gcs_blob_path.encode('utf-8')
    with open(ouput_file_path, 'wb') as output_file:
      output_file.write(env_aead.decrypt(ciphertext, associated_data))

  else:
    logging.error(
        'Error mode not supported. Please choose "encrypt" or "decrypt".')
    return 1


def _get_bucket_and_object(gcs_blob_path):
  """Extract bucket and object name from a GCS blob path.

  Args:
    gcs_blob_path: path to a GCS blob

  Returns:
    The bucket and object name of the GCS blob
  """
  if not gcs_blob_path.startswith(_GCS_PATH_PREFIX):
    logging.error('GCS blob paths must start with gs://, got %s', gcs_blob_path)
    return 1
  path = gcs_blob_path[len(_GCS_PATH_PREFIX):]
  parts = path.split('/', 1)
  if len(parts) < 2:
    logging.error(
        'GCS blob paths must be in format gs://bucket-name/object-name, got %s',
        gcs_blob_path)
    return 1
  return parts[0], parts[1]

if __name__ == '__main__':
  app.run(main)
# [END gcs-envelope-aead-example]
