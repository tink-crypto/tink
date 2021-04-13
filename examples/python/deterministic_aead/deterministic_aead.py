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
# [START deterministic-aead-example]
"""A command-line utility for encrypting small files with Determinsitic AEAD.

It loads cleartext keys from disk - this is not recommended!

It requires 4 arguments:
  mode: Can be "encrypt" or "decrypt" to encrypt/decrypt the input to the
        output.
  key-file: Read the key material from this file.
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
from tink import cleartext_keyset_handle
from tink import daead


def main(argv):
  if len(argv) != 5 and len(argv) != 6:
    raise app.UsageError(
        'Expected 4 or 5 arguments, got %d.\n'
        'Usage: %s encrypt/decrypt key-file input-file output-file '
        '[associated-data]' % (len(argv) - 1, argv[0]))

  mode = argv[1]
  key_file_path = argv[2]
  input_file_path = argv[3]
  output_file_path = argv[4]
  associated_data = b'' if len(argv) == 5 else bytes(argv[5], 'utf-8')

  # Initialise Tink
  try:
    daead.register()
  except tink.TinkError as e:
    logging.error('Error initialising Tink: %s', e)
    return 1

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
    cipher = keyset_handle.primitive(daead.DeterministicAead)
  except tink.TinkError as e:
    logging.error('Error creating primitive: %s', e)
    return 1

  with open(input_file_path, 'rb') as input_file:
    input_data = input_file.read()
    if mode == 'decrypt':
      output_data = cipher.decrypt_deterministically(
          input_data, associated_data)
    elif mode == 'encrypt':
      output_data = cipher.encrypt_deterministically(
          input_data, associated_data)
    else:
      logging.error(
          'Error mode not supported. Please choose "encrypt" or "decrypt".')
      return 1

    with open(output_file_path, 'wb') as output_file:
      output_file.write(output_data)

if __name__ == '__main__':
  app.run(main)
# [END deterministic-aead-example]
