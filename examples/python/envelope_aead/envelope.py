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
# [START envelope-example]
"""A command-line utility for encrypting small files using envelope encryption with GCP.

It requires five arguments:
  mode: Can be "encrypt" or "decrypt" to encrypt/decrypt the input to the
        output.
  kek-uri: Use this Cloud KMS' key as the key-encrypting-key for envelope
        encryption.
  gcp-credential-file: Use this JSON credential file to connect to Cloud KMS.
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
        'Usage: %s encrypt/decrypt kek-uri gcp-credential-file '
        'input-file output-file' % (len(argv) - 1, argv[0]))

  mode = argv[1]
  kek_uri = argv[2]
  gcp_credential_file = argv[3]
  input_file_path = argv[4]
  output_file_path = argv[5]

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
# [END envelope-example]
