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
"""A command-line utility for envelope encryption with GCP.

It requires 5 arguments:
  mode: Can be "encrypt" or "decrypt" to encrypt/decrypt the input to the
        output.
  gcp-credentials: Name of the file with the GCP credentials in JSON.
  key-uri: The key-uri used for envelope encryption.
  input-file: Read the input from this file.
  output-file: Write the result to this file.
"""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from absl import app
from absl import logging

import tink
from tink import aead
from tink.integration import gcpkms


def main(argv):
  if len(argv) != 6:
    raise app.UsageError(
        'Expected 5 arguments, got %d.\n'
        'Usage: %s gcp-credentials key-uri input-file output-file [decrypt]' %
        (len(argv) - 1, argv[0]))

  mode = argv[1]
  gcp_credentials = argv[2]
  key_uri = argv[3]
  input_file_path = argv[4]
  output_file_path = argv[5]

  # Initialise Tink.
  try:
    aead.register()
  except tink.TinkError as e:
    logging.error('Error initialising Tink: %s', e)
    return 1

  # Read the GCP credentials and setup client
  try:
    gcp_client = gcpkms.GcpKmsClient(key_uri, gcp_credentials)
    gcp_aead = gcp_client.get_aead(key_uri)
  except tink.TinkError as e:
    logging.error('Error initializing GCP client: %s', e)
    return 1

  # Create envelope AEAD primitive using AES256 GCM for encrypting the data
  try:
    key_template = aead.aead_key_templates.AES256_GCM
    env_aead = aead.KmsEnvelopeAead(key_template, gcp_aead)
  except tink.TinkError as e:
    logging.error('Error creating primitive: %s', e)
    return 1

  with open(input_file_path, 'rb') as input_file:
    input_data = input_file.read()
    if mode == 'decrypt':
      output_data = env_aead.decrypt(input_data, b'envelope_example')
    elif mode == 'encrypt':
      output_data = env_aead.encrypt(input_data, b'envelope_example')
    else:
      logging.error(
          'Error mode not supported. Please choose "encrypt" or "decrypt".')
      return 1

    with open(output_file_path, 'wb') as output_file:
      output_file.write(output_data)

if __name__ == '__main__':
  app.run(main)
