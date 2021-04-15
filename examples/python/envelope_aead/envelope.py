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
# [START envelope-example]
"""A command-line utility for encrypting small files using envelope encryption with GCP."""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

from absl import app
from absl import flags
from absl import logging

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
flags.DEFINE_string('input_path', None, 'Path to the input file.')
flags.DEFINE_string('output_path', None, 'Path to the output file.')
flags.DEFINE_string('associated_data', None,
                    'Optional associated data used for the encryption.')


def main(argv):
  del argv  # Unused.

  associated_data = b'' if not FLAGS.associated_data else bytes(
      FLAGS.associated_data, 'utf-8')

  # Initialise Tink
  try:
    aead.register()
  except tink.TinkError as e:
    logging.error('Error initialising Tink: %s', e)
    return 1

  # Read the GCP credentials and setup client
  try:
    gcpkms.GcpKmsClient.register_client(
        FLAGS.kek_uri, FLAGS.gcp_credential_path)
  except tink.TinkError as e:
    logging.error('Error initializing GCP client: %s', e)
    return 1

  # Create envelope AEAD primitive using AES256 GCM for encrypting the data
  try:
    template = aead.aead_key_templates.create_kms_envelope_aead_key_template(
        kek_uri=FLAGS.kek_uri,
        dek_template=aead.aead_key_templates.AES256_GCM)
    handle = tink.KeysetHandle.generate_new(template)
    env_aead = handle.primitive(aead.Aead)
  except tink.TinkError as e:
    logging.error('Error creating primitive: %s', e)
    return 1

  with open(FLAGS.input_path, 'rb') as input_file:
    input_data = input_file.read()
    if FLAGS.mode == 'decrypt':
      output_data = env_aead.decrypt(input_data, associated_data)
    elif FLAGS.mode == 'encrypt':
      output_data = env_aead.encrypt(input_data, associated_data)
    else:
      logging.error(
          'Error mode not supported. Please choose "encrypt" or "decrypt".')
      return 1

    with open(FLAGS.output_path, 'wb') as output_file:
      output_file.write(output_data)

if __name__ == '__main__':
  flags.mark_flags_as_required([
      'mode', 'kek_uri', 'gcp_credential_path', 'input_path', 'output_path'])
  app.run(main)
# [END envelope-example]
