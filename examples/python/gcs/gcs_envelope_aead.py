# Copyright 2021 Google LLC
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
# [START gcs-envelope-aead-example]
"""A command-line utility for performing file encryption using GCS.

It is inteded for use with small files, utilizes envelope encryption and
facilitates ciphertexts stored in GCS.
"""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from absl import app
from absl import flags
from absl import logging
from google.cloud import storage

import tink
from tink import aead
from tink.integration import gcpkms


FLAGS = flags.FLAGS

flags.DEFINE_enum('mode', None, ['encrypt', 'decrypt'],
                  'The operation to perform.')
flags.DEFINE_string('kek_uri', None,
                    'The Cloud KMS URI of the key encryption key.')
flags.DEFINE_string('gcp_credential_path', None,
                    'Path to the GCP credentials JSON file.')
flags.DEFINE_string('gcp_project_id', None,
                    'The ID of the GCP project hosting the GCS blobs.')
flags.DEFINE_string('local_path', None, 'Path to the local file.')
flags.DEFINE_string('gcs_blob_path', None, 'Path to the GCS blob.')


_GCS_PATH_PREFIX = 'gs://'


def main(argv):
  del argv  # Unused.

  # Initialise Tink
  try:
    aead.register()
  except tink.TinkError as e:
    logging.exception('Error initialising Tink: %s', e)
    return 1

  # Read the GCP credentials and setup client
  try:
    gcpkms.GcpKmsClient.register_client(
        FLAGS.kek_uri, FLAGS.gcp_credential_path)
  except tink.TinkError as e:
    logging.exception('Error initializing GCP client: %s', e)
    return 1

  # Create envelope AEAD primitive using AES256 GCM for encrypting the data
  try:
    template = aead.aead_key_templates.create_kms_envelope_aead_key_template(
        kek_uri=FLAGS.kek_uri,
        dek_template=aead.aead_key_templates.AES256_GCM)
    handle = tink.KeysetHandle.generate_new(template)
    env_aead = handle.primitive(aead.Aead)
  except tink.TinkError as e:
    logging.exception('Error creating primitive: %s', e)
    return 1

  storage_client = storage.Client.from_service_account_json(
      FLAGS.gcp_credential_path)

  try:
    bucket_name, object_name = _get_bucket_and_object(FLAGS.gcs_blob_path)
  except ValueError as e:
    logging.exception('Error parsing GCS blob path: %s', e)
    return 1
  bucket = storage_client.bucket(bucket_name)
  blob = bucket.blob(object_name)
  associated_data = FLAGS.gcs_blob_path.encode('utf-8')

  if FLAGS.mode == 'encrypt':
    with open(FLAGS.local_path, 'rb') as input_file:
      output_data = env_aead.encrypt(input_file.read(), associated_data)
    blob.upload_from_string(output_data)

  elif FLAGS.mode == 'decrypt':
    ciphertext = blob.download_as_bytes()
    with open(FLAGS.local_path, 'wb') as output_file:
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

  Raises:
    ValueError: If gcs_blob_path parsing fails.
  """
  if not gcs_blob_path.startswith(_GCS_PATH_PREFIX):
    raise ValueError(
        f'GCS blob paths must start with gs://, got {gcs_blob_path}')
  path = gcs_blob_path[len(_GCS_PATH_PREFIX):]
  parts = path.split('/', 1)
  if len(parts) < 2:
    raise ValueError(
        'GCS blob paths must be in format gs://bucket-name/object-name, '
        f'got {gcs_blob_path}')
  return parts[0], parts[1]

if __name__ == '__main__':
  flags.mark_flags_as_required([
      'mode', 'kek_uri', 'gcp_credential_path', 'gcp_project_id', 'local_path',
      'gcs_blob_path'])
  app.run(main)
# [END gcs-envelope-aead-example]
