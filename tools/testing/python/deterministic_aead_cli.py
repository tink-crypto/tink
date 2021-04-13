# Copyright 2020 Google LLC
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
"""A command-line utility for testing DAEAD-primitives.

It requires 5 arguments:
   keyset-file:  name of the file with the keyset to be used
                 for encrypting/decrypting
   operation: the actual DeterminisiticAead-operation, i.e.
              "encryptdeterministically" or "decryptdeterministically"
   input-file:  name of the file that contains plaintext to be encrypted or the
                encrypted text to be decrypted
   associated-data-file: name of the file that contains
                        associated-data used for encryption/decryption
   output-file:  name of the output file for the resulting encryptedtext
"""

from __future__ import absolute_import
from __future__ import division
# Placeholder for import for type annotations
from __future__ import print_function

# Special imports
from absl import app
from absl import flags
from absl import logging
import tink

from tink import cleartext_keyset_handle
from tink import daead

FLAGS = flags.FLAGS


def read_keyset(keyset_filename):
  """Load a keyset from a file.

  Args:
    keyset_filename: A path to a keyset file

  Returns:
    A KeysetHandle of the file's keyset
  Raises:
    TinkError: if the file is not valid
    IOError: if the file does not exist
  """
  with open(keyset_filename, 'rb') as keyset_file:
    text = keyset_file.read()
    keyset = cleartext_keyset_handle.read(
        tink.BinaryKeysetReader(text))
  return keyset


def main(argv):
  if len(argv) != 6:
    raise app.UsageError(
        'Expected 5 arguments, got %d.\n'
        'Usage: %s keyset-file operation input-file associated-data-file'
        'output-file' % (len(argv) - 1, argv[0]))

  keyset_filename = argv[1]
  operation = argv[2]
  input_filename = argv[3]
  associated_data_filename = argv[4]
  output_filename = argv[5]

  logging.info(
      'Using keyset from file %s to DAEAD-%s file %s with associated data '
      'from file %s.\nThe resulting output will be written to file %s',
      keyset_filename, operation, input_filename, associated_data_filename,
      output_filename)

  # Initialise Tink
  try:
    daead.register()
  except tink.TinkError as e:
    logging.error('Error initialising Tink: %s', e)
    return 1

  # Read the keyset into keyset_handle
  try:
    keyset_handle = read_keyset(keyset_filename)
  except tink.TinkError as e:
    logging.error('Error reading key: %s', e)
    return 1

  # Get the primitive
  try:
    cipher = keyset_handle.primitive(daead.DeterministicAead)
  except tink.TinkError as e:
    logging.error('Error creating primitive: %s', e)
    return 1

  # Read the input files
  with open(input_filename, 'rb') as input_file:
    input_data = input_file.read()
  with open(associated_data_filename, 'rb') as associated_data_file:
    aad = associated_data_file.read()

  # Compute the output
  if operation.lower() == 'encryptdeterministically':
    try:
      output_data = cipher.encrypt_deterministically(input_data, aad)
    except tink.TinkError as e:
      logging.error('Error encrypting the input: %s', e)
      return 1
  elif operation.lower() == 'decryptdeterministically':
    try:
      output_data = cipher.decrypt_deterministically(input_data, aad)
    except tink.TinkError as e:
      logging.error('Error decrypting the input: %s', e)
      return 1
  else:
    logging.error(
        'Did not recognise operation %s.\n'
        'Expected either "encrypt" or "decrypt"', operation)
    return 1

  with open(output_filename, 'wb') as output_file:
    output_file.write(output_data)

  logging.info('All done.')


if __name__ == '__main__':
  app.run(main)
