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
# [START encrypted-keyset-example]
"""A command-line utility for generating, encrypting and storing keysets.

It requires the following arguments:
  mode: Can be "generate", "encrypt" or "decrypt". If mode is "generate", it
       will generate a keyset, encrypt it and store it in the key-file argument.
       If mode is "encrypt" or "decrypt", it will read and decrypt an keyset
       from the key-file argument, and use it to encrypt or decrypt the
       input-file argument.
  key-file: Read the encrypted key material from this file.
  kek-uri: Use this KEK URI in Cloud KMS to encrypt/decrypt the key file.
  gcp-credential-file: USe this JSON credential file to connect to Cloud KMS.
  input-file: If mode is "encrypt" or "decrypt", read the input from this file.
  output-file: If mode is "encrypt" or "decrypt", write the result to this file.
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
  if len(argv) != 5 and len(argv) != 7:
    raise app.UsageError(
        'Invalid arguments.\n'
        'Usage: %s generate key-file kek-uri gcp-credential-file.\n'
        'Usage: %s encrypt/decrypt key-file kek-uri gcp-credential-file '
        'input-file output-file.' % (argv[0], argv[0])
        )

  mode = argv[1]
  if mode not in ('encrypt', 'decrypt', 'generate'):
    raise app.UsageError(
        'The first argument should be either encrypt, decrypt or generate')

  key_file_path = argv[2]
  kek_uri = argv[3]
  gcp_credential_file = argv[4]
  input_file_path = argv[5] if len(argv) == 7 else None
  output_file_path = argv[6] if len(argv) == 7 else None

  # Initialise Tink
  try:
    aead.register()
  except tink.TinkError as e:
    logging.error('Error initialising Tink: %s', e)
    return 1

  # Read the GCP credentials and set up a client
  try:
    gcpkms.GcpKmsClient.register_client(kek_uri, gcp_credential_file)
  except tink.TinkError as e:
    logging.error('Error initializing GCP client: %s', e)
    return 1

  # Create an AEAD primitive from the key-encryption key (KEK) for encrypting
  # Tink keysets
  try:
    handle = tink.KeysetHandle.generate_new(
        aead.aead_key_templates.create_kms_aead_key_template(key_uri=kek_uri))
    gcp_aead = handle.primitive(aead.Aead)
  except tink.TinkError as e:
    logging.exception('Error creating KMS AEAD primitive: %s', e)
    return 1

  if mode == 'generate':
    # [START generate-a-new-keyset]
    # Generate a new keyset
    try:
      key_template = aead.aead_key_templates.AES128_GCM
      keyset_handle = tink.KeysetHandle.generate_new(key_template)
    except tink.TinkError as e:
      logging.exception('Error creating primitive: %s', e)
      return 1
    # [END generate-a-new-keyset]

    # [START encrypt-a-keyset]
    # Encrypt the keyset_handle with the remote key-encryption key (KEK)
    with open(key_file_path, 'wt') as keyset_file:
      try:
        keyset_handle.write(tink.JsonKeysetWriter(keyset_file), gcp_aead)
      except tink.TinkError as e:
        logging.exception('Error writing key: %s', e)
        return 1
    return 0
    # [END encrypt-a-keyset]

  # Use the keyset to encrypt/decrypt data

  # Read the encrypted keyset into a keyset_handle
  with open(key_file_path, 'rt') as keyset_file:
    try:
      text = keyset_file.read()
      keyset_handle = tink.KeysetHandle.read(
          tink.JsonKeysetReader(text), gcp_aead)
    except tink.TinkError as e:
      logging.exception('Error reading key: %s', e)
      return 1

  # Get the primitive
  try:
    cipher = keyset_handle.primitive(aead.Aead)
  except tink.TinkError as e:
    logging.error('Error creating primitive: %s', e)
    return 1

  with open(input_file_path, 'rb') as input_file:
    input_data = input_file.read()
    if mode == 'decrypt':
      output_data = cipher.decrypt(input_data, b'encrypted-keyset-example')
    elif mode == 'encrypt':
      output_data = cipher.encrypt(input_data, b'encrypted-keyset-example')
    else:
      logging.error(
          'Error mode not supported. Please choose "encrypt" or "decrypt".')
      return 1

    with open(output_file_path, 'wb') as output_file:
      output_file.write(output_data)

if __name__ == '__main__':
  app.run(main)
# [END encrypted-keyset-example]
