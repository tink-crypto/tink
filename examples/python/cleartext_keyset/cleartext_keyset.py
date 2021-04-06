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
# [START cleartext-keyset-example]
"""A command-line utility for generating, storing and using cleartext AES128_GCM keysets.

It loads cleartext keys from disk - this is not recommended!

It requires the following arguments:
  mode: Can be "generate", "encrypt" or "decrypt".
  key-file: Read/write the key material from this file.
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
from tink import cleartext_keyset_handle


def main(argv):
  if len(argv) != 3 and len(argv) != 5:
    raise app.UsageError(
        'Invalid arguments.\n'
        'Usage: %s generate key-file.\n'
        'Usage: %s encrypt/decrypt key-file '
        'input-file output-file.' % (argv[0], argv[0])
        )

  mode = argv[1]
  if mode not in ('encrypt', 'decrypt', 'generate'):
    raise app.UsageError(
        'The first argument should be either encrypt, decrypt or generate')

  key_file_path = argv[2]
  input_file_path = argv[3] if len(argv) == 5 else None
  output_file_path = argv[4] if len(argv) == 5 else None

  # Initialise Tink
  try:
    aead.register()
  except tink.TinkError as e:
    logging.error('Error initialising Tink: %s', e)
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

    # [START store-a-cleartext-keyset]
    with open(key_file_path, 'wt') as keyset_file:
      try:
        cleartext_keyset_handle.write(
            tink.JsonKeysetWriter(keyset_file), keyset_handle)
      except tink.TinkError as e:
        logging.exception('Error writing key: %s', e)
        return 1
    return 0
    # [END store-a-cleartext-keyset]

  # Use the input keyset to encrypt/decrypt data

  # Read the keyset into a keyset_handle
  with open(key_file_path, 'rt') as keyset_file:
    try:
      text = keyset_file.read()
      keyset_handle = cleartext_keyset_handle.read(tink.JsonKeysetReader(text))
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
      output_data = cipher.decrypt(input_data, b'envelope_example')
    elif mode == 'encrypt':
      output_data = cipher.encrypt(input_data, b'envelope_example')
    else:
      logging.error(
          'Error mode not supported. Please choose "encrypt" or "decrypt".')
      return 1

    with open(output_file_path, 'wb') as output_file:
      output_file.write(output_data)

if __name__ == '__main__':
  app.run(main)
# [END cleartext-keyset-example]
